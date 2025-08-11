#include <IMU.h>  // Inertial Measurement Unit (IMU) library
#include <LoRaWAN.h>

LoRaModem modem;

void setup() {
    Serial.begin(115200);

    modem.begin(EU868);
    modem.joinOTAA(appEui, appKey);

    // additional transmission parameters...
    // in case of a custom gateway implementation, transmission intervals can be
    // lowered...
    Serial.println("Setup completed!");
}

bool computeImpact() {
    digitalWrite(PIN_TRIGGER, LOW);
    delayMicroseconds(2);
    digitalWrite(PIN_TRIGGER, HIGH);
    delayMicroseconds(10);
    digitalWrite(PIN_TRIGGER, LOW);

    // Read the pulse duration and compute the proportion:
    int duration = pulseIn(PIN_ECHO, HIGH);

    float distance = duration / 58.0;  // floating point division

    return (distance > DISTANCE_DISCRIMINANT);
}

const ANCHOR_NODES = 3;  // number of anchor nodes (>= 3, see theory)
float triangulation_RSSI[ANCHOR_NODES];
float previous_position[2];  // (x, y)
float current_position[2];

float IMU_accelerometer_measurements[3];
float IMU_gyroscope_measurements[3];
const PREVIOUS_OUTCOMES_VERSIONS = 5;  // versioning system implementation
float previous_IMU_outcomes[PREVIOUS_OUTCOMES_VERSIONS];
float current_IMU_outcome;

Forklift forklift;
int assigned_docking_station;

void loop() {
    enum GPS_coverage = check_GPS_coverage();
    if (GPS_coverage == GOOD) {
        current_position = get_GPS_position();
    } else {
        // Perform triangulation
        for (int i = 0; i < ANCHOR_NODES; i++) {
            // collect the RSSI from broadcast anchor nodes' transmissions
            triangulation_RSSI[i] = collect_RSSI(i);
        }

        // And finally compute an output position (x, y)
        current_position = triangulate(triangulation_RSSI);
    }

    // Let's now use the Inertial Measurement Unit to collect directionality
    IMU_accelerometer_measurements[0] = IMU.getAccelerometerOffset(X_AXIS);
    IMU_accelerometer_measurements[1] = IMU.getAccelerometerOffset(Y_AXIS);
    IMU_accelerometer_measurements[2] = IMU.getAccelerometerOffset(Z_AXIS);
    IMU_gyroscope_measurements[0] = IMU.getGyroOffset(X_AXIS);
    IMU_gyroscope_measurements[1] = IMU.getGyroOffset(Y_AXIS);
    IMU_gyroscope_measurements[2] = IMU.getGyroOffset(Z_AXIS);

    // And finally compute a meaningful outcome from the IMU
    current_IMU_outcome = compute_IMU_model(IMU_accelerometer_measurements,
                                            IMU_gyroscope_measurements);
    // In which we assumed a meaningful mathematical model describing the IMU's
    // measurements have been collectively used to come out with a final outcome

    // Let's implement a sketched versioning system: we will first compute the
    // average of the previous 5 measurements coming out of the IMU
    float previous_IMU_avg = 0;
    for (int i = 0; i < PREVIOUS_OUTCOMES_VERSIONS; i++) {
        previous_IMU_avg += previous_IMU_outcomes[i];
    }
    previous_IMU_avg /= PREVIOUS_OUTCOMES_VERSIONS;

    // and check for meaningful differences coming out of the IMU, impact
    // detection, triangulation or GPS tracking
    bool meaningful_difference_IMU =
        compare_IMU(previous_IMU_avg, current_IMU_outcome);
    bool meaningful_difference_position =
        euclidean_distance(current_position, previous_position);
    bool impact_detected = computeImpact();
    bool battery_status = forklift.battery.getStatus();

    if (meaningful_difference_IMU || meaningful_difference_position ||
        impact_detected) {
        msg = {
            IMU_outcome = current_IMU_outcome,
            position = current_position,
            impact = impact_detected,
            battery = battery_status
        }

        modem.beginPacket();
        modem.print(msg);
        modem.endPacket(true);
    }

    // And finally update local storage for the next versioning cycle
    update_local_state(current_IMU_outcome, current_position, impact_detected, battery_status);

    // return back to the docking station if battery status is poor
    if (battery_status == LOW) {
        forklift.move(assigned_docking_station);
    }

    delay(...);
}