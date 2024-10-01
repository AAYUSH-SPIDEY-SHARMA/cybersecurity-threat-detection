import json
import time
from kafka import KafkaProducer, KafkaConsumer
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import lime
import lime.lime_tabular
import subprocess
import requests  # For SIEM integration

# Kafka Configuration
KAFKA_BOOTSTRAP_SERVERS = 'localhost:9092'
KAFKA_TOPIC = 'cyber-security-topic'

# Anomaly Detection Model Configuration
CONTAMINATION_RATE = 0.1

# Feature Engineering - Extract additional features
def extract_features(log_entry):
    """
    Extract features from a log entry, including network metadata like IP and ports.

    Args:
        log_entry (dict): A log entry.

    Returns:
        np.array: The extracted features.
    """
    packet_size = log_entry.get('packet_size', 0)
    src_ip = log_entry.get('src_ip', '0.0.0.0')  # Simulated IP feature
    dst_ip = log_entry.get('dst_ip', '0.0.0.0')  # Simulated IP feature
    src_port = log_entry.get('src_port', 0)
    dst_port = log_entry.get('dst_port', 0)
    
    location = [0, 0]
    if log_entry['location'] == 'India':
        location = [1, 0]
    elif log_entry['location'] == 'USA':
        location = [0, 1]
    
    event_type = 1 if log_entry['event_type'] == 'login' else 2
    time_struct = time.strptime(log_entry['timestamp'], '%Y-%m-%dT%H:%M:%S')
    hour = time_struct.tm_hour
    day = time_struct.tm_yday

    return np.array([packet_size, src_port, dst_port] + location + [event_type, hour, day])

# Kafka Producer - send network logs
def send_data_to_kafka(data):
    """
    Send data to Kafka.

    Args:
        data (dict): The data to send.
    """
    producer = KafkaProducer(bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS, 
                             value_serializer=lambda v: json.dumps(v).encode('utf-8'))
    producer.send(KAFKA_TOPIC, value=data)
    producer.flush()

# Simulated Network Log Data Function
def simulate_network_data():
    """
    Simulate network log data with extended metadata (IP, ports).
    """
    network_data = [
        {"event_type": "login", "user": "user123", "timestamp": "2024-10-01T10:00:00", "location": "India", "packet_size": 150, "src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "src_port": 443, "dst_port": 8080},
        {"event_type": "data_transfer", "user": "user234", "timestamp": "2024-10-01T10:05:00", "location": "USA", "packet_size": 1024, "src_ip": "172.16.0.2", "dst_ip": "10.0.0.1", "src_port": 80, "dst_port": 8080},
        {"event_type": "login", "user": "user123", "timestamp": "2024-10-01T10:15:00", "location": "India", "packet_size": 300, "src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "src_port": 443, "dst_port": 8080},
        {"event_type": "suspicious_login", "user": "user999", "timestamp": "2024-10-01T10:20:00", "location": "Unknown", "packet_size": 2048, "src_ip": "0.0.0.0", "dst_ip": "10.0.0.1", "src_port": 0, "dst_port": 8080}
    ]
    for entry in network_data:
        send_data_to_kafka(entry)
        time.sleep(1)  # Simulate delay in sending logs

# Autoencoder Deep Learning Model for Anomaly Detection
def build_autoencoder(input_dim):
    """
    Build an autoencoder model for anomaly detection.

    Args:
        input_dim (int): The number of input features.

    Returns:
        Sequential: The compiled autoencoder model.
    """
    model = Sequential()
    model.add(Dense(16, activation='relu', input_shape=(input_dim,)))
    model.add(Dense(8, activation='relu'))
    model.add(Dense(4, activation='relu'))
    model.add(Dense(8, activation='relu'))
    model.add(Dense(16, activation='relu'))
    model.add(Dense(input_dim, activation='sigmoid'))
    
    model.compile(optimizer='adam', loss='mse')
    return model

# Train the Autoencoder Anomaly Detection Model and Random Forest Classifier
def train_models():
    """
    Train an autoencoder model and a Random Forest classifier for enhanced anomaly detection.

    Returns:
        autoencoder: The trained autoencoder model.
        rf_classifier: The trained Random Forest classifier.
        scaler: The standard scaler for feature scaling.
        threshold: Anomaly detection threshold based on validation data.
    """
    # Example data - replace with actual network data
    normal_user_behavior_data = np.array([
        extract_features({"event_type": "login", "user": "user123", "timestamp": "2024-10-01T10:00:00", "location": "India", "packet_size": 150, "src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "src_port": 443, "dst_port": 8080}),
        extract_features({"event_type": "data_transfer", "user": "user234", "timestamp": "2024-10-01T10:05:00", "location": "USA", "packet_size": 1024, "src_ip": "172.16.0.2", "dst_ip": "10.0.0.1", "src_port": 80, "dst_port": 8080}),
        extract_features({"event_type": "login", "user": "user123", "timestamp": "2024-10-01T10:15:00", "location": "India", "packet_size": 300, "src_ip": "192.168.1.10", "dst_ip": "10.0.0.1", "src_port": 443, "dst_port": 8080}),
        extract_features({"event_type": "data_transfer", "user": "user234", "timestamp": "2024-10-01T10:25:00", "location": "USA", "packet_size": 512, "src_ip": "172.16.0.2", "dst_ip": "10.0.0.1", "src_port": 80, "dst_port": 8080})
    ])
    
    X_train, X_test = train_test_split(normal_user_behavior_data, test_size=0.2)
    
    # Feature Scaling
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train Autoencoder
    autoencoder = build_autoencoder(X_train_scaled.shape[1])
    autoencoder.fit(X_train_scaled, X_train_scaled, epochs=50, batch_size=2, validation_data=(X_test_scaled, X_test_scaled))

    # Calculate threshold based on validation loss
    validation_losses = [np.mean(np.abs(X_test_scaled[i] - autoencoder.predict(X_test_scaled[i].reshape(1, -1)))) for i in range(len(X_test_scaled))]
    threshold = np.mean(validation_losses) + 3 * np.std(validation_losses)

    # Train Random Forest Classifier
    labels = [0 if i < len(X_train_scaled) // 2 else 1 for i in range(len(X_train_scaled))]  # Fake labels (normal, abnormal)
    rf_classifier = RandomForestClassifier()
    rf_classifier.fit(X_train_scaled, labels)
    
    return autoencoder, rf_classifier, scaler, threshold

# Kafka Consumer to Process Real-time Logs and Detect Anomalies
def process_data(autoencoder, rf_classifier, scaler, threshold):
    """
    Process data from Kafka and detect anomalies using the trained models.

    Args:
        autoencoder: The trained autoencoder model.
        rf_classifier: The trained Random Forest classifier.
        scaler: The standard scaler used for feature scaling.
        threshold: The threshold for anomaly detection.
    """
    consumer = KafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
        auto_offset_reset='latest',
        enable_auto_commit=True,
        group_id='cybersecurity-group',
        value_deserializer=lambda x: json.loads(x.decode('utf-8'))
    )

    batch_size = 5  # Define batch size for processing logs
    batch = []
    
    for message in consumer:
        log_entry = message.value
        batch.append(log_entry)

        if len(batch) >= batch_size:
            for log in batch:
                print(f"Processing log entry: {log}")
                
                features = extract_features(log)
                features_scaled = scaler.transform([features])

                # Autoencoder for anomaly detection
                reconstruction = autoencoder.predict(features_scaled)
                loss = np.mean(np.abs(reconstruction - features_scaled))

                if loss > threshold:
                    # Refine with Random Forest Classifier
                    prediction = rf_classifier.predict(features_scaled)
                    if prediction == 1:  # Detected anomaly
                        print(f"Anomaly detected in log entry: {log}")
                        trigger_response(log, loss)
            
            batch.clear()  # Clear the batch after processing

# Trigger Response Function for Anomalies
def trigger_response(log_entry, loss):
    """
    Trigger an appropriate response for detected anomalies.

    Args:
        log_entry (dict): The log entry where an anomaly was detected.
        loss (float): The loss value indicating the degree of anomaly.
    """
    print(f"Anomaly detected with loss: {loss}, triggering response for entry: {log_entry}")
    if log_entry['event_type'] == 'suspicious_login':
        block_user(log_entry['user'])
        integrate_with_siem(log_entry)

# Simulate Blocking a User
def block_user(user):
    """
    Simulate blocking a suspicious user.

    Args:
        user (str): The user ID to block.
    """
    print(f"Blocking user: {user}")
    # Example of a real-world action:
    # subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-s', user_ip, '-j', 'DROP'])

# SIEM Integration
def integrate_with_siem(log_entry):
    """
    Integrate with a SIEM system by sending the detected anomaly information.

    Args:
        log_entry (dict): The log entry where an anomaly was detected.
    """
    print(f"Integrating with SIEM for log entry: {log_entry}")
    # Simulate SIEM integration with an HTTP request (replace with real API)
    siem_api_url = 'https://siem-system/api/report_anomaly'
    payload = {
        "user": log_entry['user'],
        "event_type": log_entry['event_type'],
        "timestamp": log_entry['timestamp'],
        "severity": "high"
    }
    response = requests.post(siem_api_url, json=payload)
    print(f"SIEM response: {response.status_code}")

# Main Program Execution
if __name__ == '__main__':
    # Train the models
    autoencoder, rf_classifier, scaler, threshold = train_models()

    # Simulate network log data being sent to Kafka
    simulate_network_data()

    # Process data from Kafka and detect anomalies
    process_data(autoencoder, rf_classifier, scaler, threshold)
