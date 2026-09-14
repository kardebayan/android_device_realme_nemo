/*
 * Copyright (C) 2024 The LineageOS Project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once
#define LOG_TAG "android.hardware.biometrics.fingerprint-service.nemo"

#include <aidl/android/hardware/biometrics/fingerprint/BnSession.h>
#include <aidl/android/hardware/biometrics/fingerprint/ISessionCallback.h>
#include <log/log.h>
#include <vendor/oplus/hardware/biometrics/fingerprint/2.1/IBiometricsFingerprint.h>

#include "LockoutTracker.h"

namespace oplus_fp = ::vendor::oplus::hardware::biometrics::fingerprint::V2_1;

using IOplusBiometricsFingerprint = oplus_fp::IBiometricsFingerprint;

using ::aidl::android::hardware::biometrics::common::ICancellationSignal;
using ::aidl::android::hardware::biometrics::common::OperationContext;
using ::aidl::android::hardware::biometrics::fingerprint::PointerContext;
using ::aidl::android::hardware::keymaster::HardwareAuthToken;

namespace aidl::android::hardware::biometrics::fingerprint {

void onClientDeath(void* cookie);

class Session : public BnSession {
  public:
    Session(::android::sp<IOplusBiometricsFingerprint> device, int userId,
            std::shared_ptr<ISessionCallback> cb, LockoutTracker lockoutTracker);

    ndk::ScopedAStatus generateChallenge() override;
    ndk::ScopedAStatus revokeChallenge(int64_t challenge) override;
    ndk::ScopedAStatus enroll(const HardwareAuthToken& hat,
                              std::shared_ptr<ICancellationSignal>* out) override;
    ndk::ScopedAStatus authenticate(int64_t operationId,
                                    std::shared_ptr<ICancellationSignal>* out) override;
    ndk::ScopedAStatus detectInteraction(std::shared_ptr<ICancellationSignal>* out) override;
    ndk::ScopedAStatus enumerateEnrollments() override;
    ndk::ScopedAStatus removeEnrollments(const std::vector<int32_t>& enrollmentIds) override;
    ndk::ScopedAStatus getAuthenticatorId() override;
    ndk::ScopedAStatus invalidateAuthenticatorId() override;
    ndk::ScopedAStatus resetLockout(const HardwareAuthToken& hat) override;
    ndk::ScopedAStatus close() override;
    ndk::ScopedAStatus authenticateWithContext(int64_t operationId, const OperationContext& context,
                                               std::shared_ptr<ICancellationSignal>* out) override;
    ndk::ScopedAStatus enrollWithContext(const HardwareAuthToken& hat,
                                         const OperationContext& context,
                                         std::shared_ptr<ICancellationSignal>* out) override;
    ndk::ScopedAStatus detectInteractionWithContext(
            const OperationContext& context, std::shared_ptr<ICancellationSignal>* out) override;
    ndk::ScopedAStatus onContextChanged(const OperationContext& context) override;

    // Touch reporting is only meaningful for under-display sensors. This one sits in the power
    // button, so the framework never drives these; they exist to satisfy ISession.
    ndk::ScopedAStatus onPointerDown(int32_t pointerId, int32_t x, int32_t y, float minor,
                                     float major) override;
    ndk::ScopedAStatus onPointerUp(int32_t pointerId) override;
    ndk::ScopedAStatus onUiReady() override;
    ndk::ScopedAStatus onPointerDownWithContext(const PointerContext& context) override;
    ndk::ScopedAStatus onPointerUpWithContext(const PointerContext& context) override;
    ndk::ScopedAStatus onPointerCancelWithContext(const PointerContext& context) override;
    ndk::ScopedAStatus setIgnoreDisplayTouches(bool shouldIgnore) override;

    ndk::ScopedAStatus cancel();
    binder_status_t linkToDeath(AIBinder* binder);
    bool isClosed();

    // Callbacks from the vendor HAL.
    void onAcquired(oplus_fp::FingerprintAcquiredInfo acquiredInfo, int32_t vendorCode);
    void onAuthenticated(uint32_t fingerId, const ::android::hardware::hidl_vec<uint8_t>& token);
    void onEnrollResult(uint32_t fingerId, uint32_t remaining);
    void onEnumerate(uint32_t fingerId, uint32_t remaining);
    void onError(oplus_fp::FingerprintError error, int32_t vendorCode);
    void onRemoved(uint32_t fingerId, uint32_t remaining);
    void onSyncTemplates(const ::android::hardware::hidl_vec<uint32_t>& fingerIds);

  private:
    bool checkSensorLockout();
    void clearLockout(bool clearAttemptCounter);
    void startLockoutTimer(int64_t timeout);
    void lockoutTimerExpired();

    ::android::sp<IOplusBiometricsFingerprint> mDevice;
    ::android::sp<oplus_fp::IBiometricsFingerprintClientCallback> mVendorCb;
    LockoutTracker mLockoutTracker;
    bool mClosed = false;

    // lockout timer
    bool mIsLockoutTimerStarted = false;
    bool mIsLockoutTimerAborted = false;

    // The vendor HAL reports enrolled templates through onSyncTemplates instead of answering
    // enumerate() with onEnumerate, so keep the last set it told us about.
    std::vector<int32_t> mKnownFingers;
    bool mReceivedEnumerate = false;
    bool mReceivedCancel = false;
    std::vector<int32_t> mPendingEnumeration;

    // The user ID for which this session was created.
    int32_t mUserId;

    // Callback for talking to the framework. This callback must only be called from non-binder
    // threads to prevent nested binder calls and consequently a binder thread exhaustion.
    // Practically, it means that this callback should always be called from the worker thread.
    std::shared_ptr<ISessionCallback> mCb;

    // Binder death handler.
    AIBinder_DeathRecipient* mDeathRecipient;
};

}  // namespace aidl::android::hardware::biometrics::fingerprint
