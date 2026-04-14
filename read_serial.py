import serial
import time

try:
    ser = serial.Serial('/dev/ttyUSB0', 115200, timeout=1)
    ser.setDTR(False)
    ser.setRTS(False)
    time.sleep(0.1)
    ser.setDTR(True)
    ser.setRTS(True)
    
    start_time = time.time()
    while time.time() - start_time < 15:
        line = ser.readline().decode('utf-8', errors='ignore')
        if line:
            print(line.strip())
    ser.close()
except Exception as e:
    print(f"Error: {e}")
