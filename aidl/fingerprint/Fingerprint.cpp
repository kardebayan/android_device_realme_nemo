/*
 * Copyright (C) 2024 The LineageOS Project
 *               2024 Paranoid Android
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "Fingerprint.h"

#include <android-base/logging.h>
#include <unistd.h>

namespace aidl::android::hardware::biometrics::fingerprint {

namespace {
constexpr int SENSOR_ID = 0;
constexpr int MAX_ENROLLMENTS_PER_USER = 5;
constexpr char HW_COMPONENT_ID[] = "fingerprintSensor";
constexpr char HW_VERSION[] = "vendor/model/revision";
constexpr char FW_VERSION[] = "1.01";
constexpr char SERIAL_NUMBER[] = "00000001";
constexpr char SW_COMPONENT_ID[] = "matchingAlgorithm";
constexpr char SW_VERSION[] = "vendor/version/revision";

// The vendor service is started in parallel with us, so give it time to come up.
constexpr int GET_SERVICE_TRIES = 10;
constexpr int GET_SERVICE_RETRY_DELAY_SEC = 10;
}  // namespace

Fingerprint::Fingerprint() {
    for (int i = 0; i < GET_SERVICE_TRIES; i++) {
        mDevice = IOplusBiometricsFingerprint::tryGetService();
        if (mDevice != nullptr) break;
        sleep(GET_SERVICE_RETRY_DELAY_SEC);
    }
    CHECK(mDevice != nullptr) << "Failed to get the Oplus fingerprint service";
}

ndk::ScopedAStatus Fingerprint::getSensorProps(std::vector<SensorProps>* out) {
    std::vector<common::ComponentInfo> componentInfo = {
            {HW_COMPONENT_ID, HW_VERSION, FW_VERSION, SERIAL_NUMBER, "" /* softwareVersion */},
            {SW_COMPONENT_ID, "" /* hardwareVersion */, "" /* firmwareVersion */,
             "" /* serialNumber */, SW_VERSION}};

    common::CommonProps commonProps = {SENSOR_ID, common::SensorStrength::STRONG,
                                       MAX_ENROLLMENTS_PER_USER, componentInfo};

    *out = {{commonProps, FingerprintSensorType::POWER_BUTTON, {} /* sensorLocations */,
             false /* supportsNavigationGestures */, false /* supportsDetectInteraction */,
             false /* halHandlesDisplayTouches */, false /* halControlsIllumination */,
             std::nullopt /* touchDetectionParameters */}};

    return ndk::ScopedAStatus::ok();
}

ndk::ScopedAStatus Fingerprint::createSession(int32_t /*sensorId*/, int32_t userId,
                                              const std::shared_ptr<ISessionCallback>& cb,
                                              std::shared_ptr<ISession>* out) {
    CHECK(mSession == nullptr || mSession->isClosed()) << "Open session already exists!";

    mSession = SharedRefBase::make<Session>(mDevice, userId, cb, mLockoutTracker);
    *out = mSession;

    mSession->linkToDeath(cb->asBinder().get());

    return ndk::ScopedAStatus::ok();
}

}  // namespace aidl::android::hardware::biometrics::fingerprint
