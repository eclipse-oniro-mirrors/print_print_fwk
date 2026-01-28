# OpenHarmony Print Scan Framework

## Project Overview

OpenHarmony Print Scan Framework is a complete solution that provides printing and scanning capabilities for the OpenHarmony operating system. The framework implements print services and scan services, supports multiple device connection methods and protocols, and provides unified printing and scanning interfaces for applications.

## System Architecture

### Print System Architecture

The print system adopts a layered design, mainly including:
- Interface layer: Provides multiple interfaces such as NAPI, JNI
- Framework layer: Implements print core logic and device management
- Service layer: Provides system capability services
- Driver layer: Supports multiple printing protocols such as CUPS, IPP Everywhere

**Figure 1** Print Component Architecture Diagram

![](figures/print-architecture.png)

**Figure 2** Print Flow Diagram

![](figures/printSystemArchitecture.png)

The print logic flow is as follows:

First, the print request goes to the print framework, then from the print system framework to the print preview interface (PrintSpooler), which pulls up the print preview interface to the application layer. PrintSpooler sends an instruction to enable discovery capability to the print service (PrintSA), then PrintSA sends an instruction to enable discovery capability to the print extension interface (PrintExtension), and then PrintExtension sends an instruction to enable discovery capability to the third-party print extension interface (CustomPrintExtension) to discover printers. CustomPrintExtension reports the discovered printer information to the print service (PrintServiceAbility) and returns it to PrintSpooler. The print preview interface (PrintSpooler) sends the print task to the print service (PrintServiceAbility), then to the print extension (PrintExtension), then to the third-party print extension (CustomPrintExtension), and finally to the printer.

### Scan System Architecture

The scan system also adopts a layered design:
- Interface layer: Provides unified scanning API
- Framework layer: Implements scan core logic
- Service layer: Provides scan system capabilities
- Driver layer: Based on SANE backend, supports multiple scanning devices

**Figure 3** Scan Component Architecture Diagram

![](figures/scan-architecture.png)

**Figure 4** Scan Flow Diagram

![](figures/scanSystemArchitecture.png)

The backend of the scanning system is a driver developed based on [SANE](https://gitcode.com/openharmony/third_party_backends), which provides the ability to connect to scanners.
Third-party applications install drivers into the system sandbox through the driver installation application, and applications call the scanning framework through the system API, and the scanning service loads the backend driver to connect to the scanner.

## Directory Structure

```
print_print_fwk/
├── etc/             # Configuration files directory
│   ├── init/        # Initialization configuration
│   └── param/       # Parameter configuration
├── figures/         # Architecture diagrams
├── frameworks/      # Framework code
│   ├── ISaneBackends/   # SANE backend interfaces
│   ├── ani_util/        # Animation utilities
│   ├── helper/          # Helper utilities
│   ├── innerkitsimpl/   # Internal implementation
│   ├── kits/            # Development kits
│   ├── models/          # Data models
│   ├── ohprint/         # Print interfaces
│   └── ohscan/          # Scan interfaces
├── interfaces/      # Interface definitions
│   └── kits/            # Development interfaces
├── profile/         # Profile files
├── services/        # Service implementation
│   ├── print_service/   # Print service
│   ├── sane_service/    # SANE service
│   └── scan_service/    # Scan service
└── test/            # Test code
```

## Core Features

### Print Service

- **Device Management**: Supports USB, network printer discovery and management
- **Print Tasks**: Create, submit, monitor and cancel print tasks
- **Driver Support**: Integrates multiple print drivers such as CUPS, IPP Everywhere
- **Print Options**: Supports multiple print options such as page size, resolution, margins
- **Status Monitoring**: Real-time monitoring of printer status and task progress

### Scan Service

- **Device Discovery**: Supports USB, network scanner discovery
- **Scan Control**: Set scan parameters, start and stop scanning
- **Image Acquisition**: Get scanned image data
- **Device Management**: Add, delete and manage scanning devices
- **Status Monitoring**: Monitor scan progress and device status

## Technology Stack

- **Programming Language**: C++
- **System Framework**: OpenHarmony system capabilities
- **Print Protocols**: CUPS, IPP, USB
- **Scan Protocols**: SANE, USB, TCP/IP
- **Build System**: GN, Ninja

## Configuration Instructions

### Print Service Configuration

- Configuration file location: `etc/init/printservice.cfg`
- CUPS configuration: `etc/init/cupsd.conf`
- Enterprise mode configuration: `etc/init/cups_enterprise-files.conf`

### Scan Service Configuration

- Configuration file location: `etc/init/scanservice.cfg`
- SANE configuration: `etc/init/saneservice.cfg`

## Usage Guide

### Print Function

1. **Initialize Print Service**
   - Call the initialization interface of the print service
   - Get the print manager instance

2. **Discover Printers**
   - Call the device discovery interface
   - Listen for printer discovery events

3. **Select Printer**
   - Select from the discovered printer list
   - Get printer capabilities and options

4. **Create Print Task**
   - Set print parameters (page size, resolution, etc.)
   - Submit print files

5. **Monitor Print Task**
   - Listen for print task status changes
   - Get task progress information

### Scan Function

1. **Initialize Scan Service**
   - Call the initialization interface of the scan service

2. **Discover Scanners**
   - Call the device discovery interface
   - Get the list of available scanners

3. **Open Scanner**
   - Select the target scanner
   - Open device connection

4. **Set Scan Parameters**
   - Configure parameters such as resolution, format
   - Get options supported by the device

5. **Execute Scan**
   - Start the scanning process
   - Monitor scan progress
   - Get scan results

## Development Instructions

### Build System

The project uses GN and Ninja build systems:

```bash
# Generate build files
gn gen out

# Build project
ninja -C out
```

### Dependency Management

- CUPS printing system
- SANE scanning library
- OpenHarmony SDK

## Constraints

- To use the full functionality of the print framework, you need to apply for the `ohos.permission.PRINT` and `ohos.permission.MANAGE_PRINT_JOB` permissions.

## Testing

The project includes multiple test cases:
- Unit tests
- Functional tests
- Fuzz tests

## Contribution Guide

1. **Fork the repository**
2. **Create a feature branch**
3. **Commit your code**
4. **Create a Pull Request**

## Related Repositories

[cups](https://gitcode.com/openharmony/third_party_cups)

[backends](https://gitcode.com/openharmony/third_party_backends)

[applications_print_spooler](https://gitcode.com/openharmony/applications_print_spooler)

## License

This project is licensed under the Apache License 2.0. For details, please refer to the [LICENSE](LICENSE) file.

## Contact Information

For questions or suggestions, please contact us through:
- Project address: https://gitcode.com/openharmony/print_print_fwk
- Email: [openharmony@openharmony.io](mailto:openharmony@openharmony.io)
