# HackRF Scanner Module

The HackRF scanner module adds RF spectrum analysis capabilities to the fingerprinter tool. It identifies "hot bins" - frequency ranges with significant RF activity that can be used for device fingerprinting.

## Overview

The HackRF scanner performs wide-spectrum scanning across common frequency bands to identify active transmissions. This is particularly useful for:

- Detecting IoT devices operating on ISM bands (433MHz, 868MHz, 915MHz)
- Identifying WiFi and Bluetooth activity (2.4GHz, 5GHz)
- Finding cellular/LTE transmissions
- Discovering unknown RF devices in the environment

## Prerequisites

### Hardware
- HackRF One SDR device
- Appropriate antenna for target frequency ranges
- USB connection to host computer

### Software
1. Install HackRF tools:
   ```bash
   # Ubuntu/Debian
   sudo apt install hackrf

   # Or build from source
   git clone https://github.com/mossmann/hackrf.git
   cd hackrf/host
   mkdir build && cd build
   cmake .. && make && sudo make install
   ```

2. Set up device permissions:
   ```bash
   sudo usermod -a -G plugdev $USER
   # Then logout and login again
   ```

3. Verify device connection:
   ```bash
   hackrf_info
   ```

## Usage

### Basic RF Scanning
```bash
# Scan with HackRF module only
python -m fingerprinter --legal-ok -m hackrf 192.168.1.1

# Include RF scanning in full scan
python -m fingerprinter --legal-ok 192.168.1.1
```

### Interactive Mode
```bash
# Quick scan of common frequencies
python -m fingerprinter --legal-ok --interactive -m hackrf 192.168.1.1
```

## Frequency Ranges Scanned

The scanner covers these frequency bands:

| Band Name | Frequency Range | Description |
|-----------|----------------|-------------|
| ism_433 | 433.05-434.79 MHz | 433MHz ISM band |
| ism_868 | 863-870 MHz | 868MHz ISM band (EU) |
| ism_915 | 902-928 MHz | 915MHz ISM band (US) |
| wifi_2g4 | 2.4-2.5 GHz | 2.4GHz WiFi |
| bluetooth | 2.402-2.480 GHz | Bluetooth |
| wifi_5g_low | 5.15-5.35 GHz | 5GHz WiFi lower |
| wifi_5g_mid | 5.47-5.725 GHz | 5GHz WiFi middle |
| wifi_5g_high | 5.725-5.875 GHz | 5GHz WiFi upper |
| lte_700 | 698-798 MHz | LTE Bands 12/13/14/17 |
| lte_850 | 824-894 MHz | LTE Band 5 |
| lte_1900 | 1850-1990 MHz | LTE Bands 2/25 |
| cellular_gsm | 880-960 MHz | GSM 900 |
| cellular_dcs | 1710-1880 MHz | DCS 1800 |

## Output Format

The scanner adds `rf_scans` section to the scan report:

```json
{
  "rf_scans": [
    {
      "center_freq_hz": 433920000.0,
      "sample_rate_hz": 10000000.0,
      "bandwidth_hz": 1740000.0,
      "gain_db": 30,
      "hot_bins": [
        {
          "frequency_hz": 433920000.0,
          "power_db": -45.2,
          "bandwidth_hz": 1000000.0,
          "detection_method": "hackrf_sweep",
          "timestamp": "2024-01-01T12:00:00"
        }
      ],
      "scan_duration_sec": 8.0,
      "total_samples": 0,
      "noise_floor_db": -75.5,
      "detection_threshold_db": -63.5
    }
  ]
}
```

## Hot Bin Detection

Hot bins are identified using the following criteria:

1. **Noise Floor Calculation**: 25th percentile of power measurements
2. **Detection Threshold**: Noise floor + 12 dB
3. **Peak Detection**: Frequencies with power above threshold
4. **Filtering**: Results limited to top 25 strongest signals per band

## Technical Details

### Scanning Method
- Uses `hackrf_sweep` for wide-spectrum analysis
- 1 MHz frequency steps for comprehensive coverage
- Configurable scan duration (3s interactive, 8s full scan)
- Automatic gain control (LNA: 32dB, VGA: 30dB)

### Signal Processing
- Real-time power spectrum analysis
- Statistical noise floor estimation
- Peak detection with configurable thresholds
- Frequency domain filtering

### Performance
- **Scan Speed**: ~10 MHz/second effective
- **Frequency Resolution**: 1 MHz bins
- **Power Resolution**: ~1 dB
- **Scan Coverage**: 1 MHz to 6 GHz (HackRF limits)

## Troubleshooting

### No HackRF Device Found
```
ERROR: No HackRF boards found
```
**Solutions:**
- Check USB connection
- Verify device permissions: `ls -l /dev/bus/usb/*/*`
- Add user to plugdev group: `sudo usermod -a -G plugdev $USER`
- Try different USB port/cable

### Permission Denied
```
ERROR: hackrf_open() failed: HACKRF_ERROR_NOT_FOUND (-5)
```
**Solutions:**
- Run: `sudo udevadm control --reload-rules`
- Logout and login after adding to plugdev group
- Check udev rules in `/etc/udev/rules.d/`

### Poor Signal Quality
- **Use appropriate antenna** for target frequency
- **Reduce gain** if signals are saturated
- **Check for interference** from nearby devices
- **Improve antenna positioning**

## Future Enhancements

The current implementation provides wide-spectrum "hot bin" detection. Future versions will include:

1. **Detailed Signal Analysis**: IQ sample collection for identified hot bins
2. **Modulation Detection**: Identify signal modulation types (FSK, GFSK, etc.)
3. **Protocol Fingerprinting**: Decode and analyze specific protocols
4. **Time-Domain Analysis**: Burst pattern recognition
5. **Machine Learning**: Automated device classification

## Example Output

```
INFO     Starting HackRF spectrum analysis       hackrf.py:58
INFO     Scanning wifi_2g4: 2400.0 - 2500.0 MHz hackrf.py:84
INFO     Found 3 active frequencies in wifi_2g4  hackrf.py:95
INFO     Scanning bluetooth: 2402.0 - 2480.0 MHz hackrf.py:84
INFO     Found 1 active frequencies in bluetooth hackrf.py:95
INFO     RF scan complete: found 4 active        hackrf.py:107
         frequency bins across 2 ranges
INFO     Top active frequencies:                 hackrf.py:113
INFO       1. 2437.000 MHz: -42.3 dB             hackrf.py:115
INFO       2. 2462.000 MHz: -45.1 dB             hackrf.py:115
INFO       3. 2412.000 MHz: -48.7 dB             hackrf.py:115
INFO       4. 2442.000 MHz: -51.2 dB             hackrf.py:115
```

This identifies WiFi channels 6, 11, 1, and 7 as active in the 2.4GHz band.