/*
 * Copyright (C) 2024 The LineageOS Project
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "Session.h"

#include <cstring>
#include <functional>
#include <inttypes.h>
#include <thread>

#include "CancellationSignal.h"
#include "Legacy2Aidl.h"

using ::android::hardware::hidl_array;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;
using ::android::hardware::Void;

namespace aidl::android::hardware::biometrics::fingerprint {

namespace {
constexpr int ENROLL_TIMEOUT_SEC = 60;

static_assert(sizeof(hw_auth_token_t) == 69, "hw_auth_token_t must match the vendor HAL's uint8_t[69]");

Error toAidlError(oplus_fp::FingerprintError error, int32_t* vendorCode) {
    *vendorCode = 0;

    switch (error) {
        case oplus_fp::FingerprintError::ERROR_HW_UNAVAILABLE:
            return Error::HW_UNAVAILABLE;
        case oplus_fp::FingerprintError::ERROR_UNABLE_TO_PROCESS:
            return Error::UNABLE_TO_PROCESS;
        case oplus_fp::FingerprintError::ERROR_TIMEOUT:
            return Error::TIMEOUT;
        case oplus_fp::FingerprintError::ERROR_NO_SPACE:
            return Error::NO_SPACE;
        case oplus_fp::FingerprintError::ERROR_CANCELED:
            return Error::CANCELED;
        case oplus_fp::FingerprintError::ERROR_UNABLE_TO_REMOVE:
            return Error::UNABLE_TO_REMOVE;
        case oplus_fp::FingerprintError::ERROR_LOCKOUT:
            *vendorCode = static_cast<int32_t>(oplus_fp::FingerprintError::ERROR_LOCKOUT);
            return Error::VENDOR;
        default:
            return Error::UNKNOWN;
    }
}

AcquiredInfo toAidlAcquiredInfo(oplus_fp::FingerprintAcquiredInfo info) {
    switch (info) {
        case oplus_fp::FingerprintAcquiredInfo::ACQUIRED_GOOD:
            return AcquiredInfo::GOOD;
        case oplus_fp::FingerprintAcquiredInfo::ACQUIRED_PARTIAL:
            return AcquiredInfo::PARTIAL;
        case oplus_fp::FingerprintAcquiredInfo::ACQUIRED_INSUFFICIENT:
            return AcquiredInfo::INSUFFICIENT;
        case oplus_fp::FingerprintAcquiredInfo::ACQUIRED_IMAGER_DIRTY:
            return AcquiredInfo::SENSOR_DIRTY;
        case oplus_fp::FingerprintAcquiredInfo::ACQUIRED_TOO_SLOW:
            return AcquiredInfo::TOO_SLOW;
        case oplus_fp::FingerprintAcquiredInfo::ACQUIRED_TOO_FAST:
            return AcquiredInfo::TOO_FAST;
        case oplus_fp::FingerprintAcquiredInfo::ACQUIRED_VENDOR:
            return AcquiredInfo::VENDOR;
        default:
            return AcquiredInfo::UNKNOWN;
    }
}
}  // namespace

// Bridges the vendor HAL's callbacks onto the session that is currently open.
class VendorCallback : public oplus_fp::IBiometricsFingerprintClientCallback {
  public:
    explicit VendorCallback(Session* session) : mSession(session) {}

    Return<void> onEnrollResult(uint64_t, uint32_t fingerId, uint32_t, uint32_t remaining) {
        mSession->onEnrollResult(fingerId, remaining);
        return Void();
    }

    Return<void> onAcquired(uint64_t, oplus_fp::FingerprintAcquiredInfo acquiredInfo,
                            int32_t vendorCode) {
        mSession->onAcquired(acquiredInfo, vendorCode);
        return Void();
    }

    Return<void> onAuthenticated(uint64_t, uint32_t fingerId, uint32_t,
                                 const hidl_vec<uint8_t>& token) {
        mSession->onAuthenticated(fingerId, token);
        return Void();
    }

    Return<void> onError(uint64_t, oplus_fp::FingerprintError error, int32_t vendorCode) {
        mSession->onError(error, vendorCode);
        return Void();
    }

    Return<void> onRemoved(uint64_t, uint32_t fingerId, uint32_t, uint32_t remaining) {
        mSession->onRemoved(fingerId, remaining);
        return Void();
    }

    Return<void> onEnumerate(uint64_t, uint32_t fingerId, uint32_t, uint32_t remaining) {
        mSession->onEnumerate(fingerId, remaining);
        return Void();
    }

    Return<void> onSyncTemplates(uint64_t, const hidl_vec<uint32_t>& fingerId, uint32_t) {
        mSession->onSyncTemplates(fingerId);
        return Void();
    }

    // Unused by the framework, but part of the vendor interface.
    Return<void> onTouchUp(uint64_t) { return Void(); }
    Return<void> onTouchDown(uint64_t) { return Void(); }
    Return<void> onFingerprintCmd(int32_t, const hidl_vec<uint32_t>&, uint32_t) { return Void(); }
    Return<void> onImageInfoAcquired(uint32_t, uint32_t, uint32_t) { return Void(); }
    Return<void> onMonitorEventTriggered(uint32_t, const hidl_string&) { return Void(); }
    Return<void> onEngineeringInfoUpdated(uint32_t, const hidl_vec<uint32_t>&,
                                          const hidl_vec<hidl_string>&) {
        return Void();
    }

  private:
    Session* mSession;
};

void onClientDeath(void* cookie) {
    ALOGI("FingerprintService has died");
    Session* session = static_cast<Session*>(cookie);
    if (session && !session->isClosed()) {
        session->close();
    }
}

Session::Session(::android::sp<IOplusBiometricsFingerprint> device, int userId,
                 std::shared_ptr<ISessionCallback> cb, LockoutTracker lockoutTracker)
    : mDevice(device), mLockoutTracker(lockoutTracker), mUserId(userId), mCb(cb) {
    mDeathRecipient = AIBinder_DeathRecipient_new(onClientDeath);

    mVendorCb = new VendorCallback(this);
    mDevice->setNotify(mVendorCb);

    auto path = "/data/vendor_de/" + std::to_string(userId) + "/fpdata/";
    mDevice->setActiveGroup(mUserId, path);
}

ndk::ScopedAStatus Session::generateChallenge() {
    uint64_t challenge = mDevice->preEnroll();
    ALOGI("generateChallenge: %" PRIu64, challenge);
    mCb->onChallengeGenerated(challenge);

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::revokeChallenge(int64_t challenge) {
    ALOGI("revokeChallenge: %" PRId64, challenge);
    mDevice->postEnroll();
    mCb->onChallengeRevoked(challenge);

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::enroll(const HardwareAuthToken& hat,
                                   std::shared_ptr<ICancellationSignal>* out) {
    hw_auth_token_t authToken;
    translate(hat, authToken);

    hidl_array<uint8_t, 69> vendorHat(reinterpret_cast<const uint8_t*>(&authToken));
    oplus_fp::RequestStatus status = mDevice->enroll(vendorHat, mUserId, ENROLL_TIMEOUT_SEC);
    if (status != oplus_fp::RequestStatus::SYS_OK) {
        ALOGE("enroll failed: %d", static_cast<int32_t>(status));
        mCb->onError(Error::UNABLE_TO_PROCESS, static_cast<int32_t>(status));
    }

    *out = SharedRefBase::make<CancellationSignal>(this);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::authenticate(int64_t operationId,
                                         std::shared_ptr<ICancellationSignal>* out) {
    checkSensorLockout();

    oplus_fp::RequestStatus status = mDevice->authenticate(operationId, mUserId);
    if (status != oplus_fp::RequestStatus::SYS_OK) {
        ALOGE("authenticate failed: %d", static_cast<int32_t>(status));
        mCb->onError(Error::UNABLE_TO_PROCESS, static_cast<int32_t>(status));
    }

    *out = SharedRefBase::make<CancellationSignal>(this);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::detectInteraction(std::shared_ptr<ICancellationSignal>* out) {
    ALOGD("Detect interaction is not supported");
    mCb->onError(Error::UNABLE_TO_PROCESS, 0 /* vendorCode */);

    *out = SharedRefBase::make<CancellationSignal>(this);
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::enumerateEnrollments() {
    mReceivedEnumerate = false;
    mPendingEnumeration.clear();

    oplus_fp::RequestStatus status = mDevice->enumerate();
    if (status != oplus_fp::RequestStatus::SYS_OK) {
        ALOGE("enumerate failed: %d", static_cast<int32_t>(status));
        return ndk::ScopedAStatus::ok();
    }

    // The vendor HAL answers enumerate() with onSyncTemplates rather than onEnumerate, so fall
    // back to the template list it last reported.
    if (!mReceivedEnumerate) {
        ALOGI("No onEnumerate from vendor HAL, reporting %zu synced templates",
              mKnownFingers.size());
        mCb->onEnrollmentsEnumerated(mKnownFingers);
    }

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::removeEnrollments(const std::vector<int32_t>& enrollmentIds) {
    ALOGI("removeEnrollments, size: %zu", enrollmentIds.size());

    for (int32_t fid : enrollmentIds) {
        oplus_fp::RequestStatus status = mDevice->remove(mUserId, fid);
        if (status != oplus_fp::RequestStatus::SYS_OK) {
            ALOGE("remove failed: %d", static_cast<int32_t>(status));
        }
    }

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::getAuthenticatorId() {
    uint64_t authId = mDevice->getAuthenticatorId();
    ALOGI("getAuthenticatorId: %" PRIu64, authId);
    mCb->onAuthenticatorIdRetrieved(authId);

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::invalidateAuthenticatorId() {
    uint64_t authId = mDevice->getAuthenticatorId();
    ALOGI("invalidateAuthenticatorId: %" PRIu64, authId);
    mCb->onAuthenticatorIdInvalidated(authId);

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::resetLockout(const HardwareAuthToken& /*hat*/) {
    clearLockout(true);
    if (mIsLockoutTimerStarted) mIsLockoutTimerAborted = true;

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::cancel() {
    mReceivedCancel = false;

    oplus_fp::RequestStatus status = mDevice->cancel();
    if (status != oplus_fp::RequestStatus::SYS_OK) {
        return ndk::ScopedAStatus::fromServiceSpecificError(static_cast<int32_t>(status));
    }

    // The vendor HAL does not always raise ERROR_CANCELED, so make sure the framework sees one.
    if (!mReceivedCancel) {
        ALOGI("No ERROR_CANCELED from vendor HAL, sending our own");
        mCb->onError(Error::CANCELED, 0 /* vendorCode */);
    }

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::close() {
    mClosed = true;
    mCb->onSessionClosed();
    AIBinder_DeathRecipient_delete(mDeathRecipient);

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::authenticateWithContext(int64_t operationId,
                                                    const OperationContext& /*context*/,
                                                    std::shared_ptr<ICancellationSignal>* out) {
    return authenticate(operationId, out);
}

ndk::ScopedAStatus Session::enrollWithContext(const HardwareAuthToken& hat,
                                              const OperationContext& /*context*/,
                                              std::shared_ptr<ICancellationSignal>* out) {
    return enroll(hat, out);
}

ndk::ScopedAStatus Session::detectInteractionWithContext(
        const OperationContext& /*context*/, std::shared_ptr<ICancellationSignal>* out) {
    return detectInteraction(out);
}

ndk::ScopedAStatus Session::onContextChanged(const OperationContext& /*context*/) {
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onPointerDown(int32_t /*pointerId*/, int32_t /*x*/, int32_t /*y*/,
                                          float /*minor*/, float /*major*/) {
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onPointerUp(int32_t /*pointerId*/) {
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onUiReady() {
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onPointerDownWithContext(const PointerContext& /*context*/) {
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onPointerUpWithContext(const PointerContext& /*context*/) {
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::onPointerCancelWithContext(const PointerContext& /*context*/) {
    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Session::setIgnoreDisplayTouches(bool /*shouldIgnore*/) {
    return ndk::ScopedAStatus::ok();
}

binder_status_t Session::linkToDeath(AIBinder* binder) {
    return AIBinder_linkToDeath(binder, mDeathRecipient, this);
}

bool Session::isClosed() {
    return mClosed;
}

void Session::onEnrollResult(uint32_t fingerId, uint32_t remaining) {
    ALOGD("onEnrollResult(fid=%u, rem=%u)", fingerId, remaining);
    mCb->onEnrollmentProgress(fingerId, remaining);
}

void Session::onAcquired(oplus_fp::FingerprintAcquiredInfo acquiredInfo, int32_t vendorCode) {
    AcquiredInfo result = toAidlAcquiredInfo(acquiredInfo);
    ALOGD("onAcquired(%hhd, %d)", result, vendorCode);
    mCb->onAcquired(result, vendorCode);
}

void Session::onAuthenticated(uint32_t fingerId, const hidl_vec<uint8_t>& token) {
    ALOGD("onAuthenticated(fid=%u)", fingerId);

    if (fingerId != 0) {
        HardwareAuthToken authToken;
        if (token.size() == sizeof(hw_auth_token_t)) {
            hw_auth_token_t hat;
            memcpy(&hat, token.data(), sizeof(hat));
            translate(hat, authToken);
        } else {
            ALOGE("Unexpected auth token size: %zu", token.size());
        }

        mCb->onAuthenticationSucceeded(fingerId, authToken);
        mLockoutTracker.reset(true);
    } else {
        mCb->onAuthenticationFailed();
        mLockoutTracker.addFailedAttempt();
        checkSensorLockout();
    }
}

void Session::onError(oplus_fp::FingerprintError error, int32_t vendorCode) {
    if (error == oplus_fp::FingerprintError::ERROR_CANCELED) {
        mReceivedCancel = true;
    }

    int32_t mappedVendorCode = 0;
    Error result = toAidlError(error, &mappedVendorCode);
    if (mappedVendorCode == 0) mappedVendorCode = vendorCode;

    ALOGD("onError(%hhd, %d)", result, mappedVendorCode);
    mCb->onError(result, mappedVendorCode);
}

void Session::onRemoved(uint32_t fingerId, uint32_t remaining) {
    ALOGD("onRemoved(fid=%u, rem=%u)", fingerId, remaining);
    mCb->onEnrollmentsRemoved({static_cast<int32_t>(fingerId)});
}

void Session::onEnumerate(uint32_t fingerId, uint32_t remaining) {
    ALOGD("onEnumerate(fid=%u, rem=%u)", fingerId, remaining);
    mReceivedEnumerate = true;

    mPendingEnumeration.push_back(fingerId);
    if (remaining == 0) {
        mCb->onEnrollmentsEnumerated(mPendingEnumeration);
        mPendingEnumeration.clear();
    }
}

void Session::onSyncTemplates(const hidl_vec<uint32_t>& fingerIds) {
    ALOGD("onSyncTemplates(count=%zu)", fingerIds.size());
    mKnownFingers.assign(fingerIds.begin(), fingerIds.end());
}

bool Session::checkSensorLockout() {
    LockoutTracker::LockoutMode lockoutMode = mLockoutTracker.getMode();
    if (lockoutMode == LockoutTracker::LockoutMode::kPermanent) {
        ALOGE("Fail: lockout permanent");
        mCb->onLockoutPermanent();
        mIsLockoutTimerAborted = true;
        return true;
    }
    if (lockoutMode == LockoutTracker::LockoutMode::kTimed) {
        int64_t timeLeft = mLockoutTracker.getLockoutTimeLeft();
        ALOGE("Fail: lockout timed: %" PRId64, timeLeft);
        mCb->onLockoutTimed(timeLeft);
        if (!mIsLockoutTimerStarted) startLockoutTimer(timeLeft);
        return true;
    }
    return false;
}

void Session::clearLockout(bool clearAttemptCounter) {
    mLockoutTracker.reset(clearAttemptCounter);
    mCb->onLockoutCleared();
}

void Session::startLockoutTimer(int64_t timeout) {
    std::function<void()> action = std::bind(&Session::lockoutTimerExpired, this);
    std::thread([timeout, action]() {
        std::this_thread::sleep_for(std::chrono::milliseconds(timeout));
        action();
    }).detach();

    mIsLockoutTimerStarted = true;
}

void Session::lockoutTimerExpired() {
    if (!mIsLockoutTimerAborted) clearLockout(false);

    mIsLockoutTimerStarted = false;
    mIsLockoutTimerAborted = false;
}

}  // namespace aidl::android::hardware::biometrics::fingerprint
