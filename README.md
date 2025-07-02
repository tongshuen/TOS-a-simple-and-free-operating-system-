# TOS - Lightweight OS Project

*A lightweight open-source operating system project*

## Usage Instructions

### System Requirements
- **Runtime Environment**: Recommended to test in a virtual machine (e.g. QEMU/VirtualBox)  
- **Deployment**: Better suited as Live USB/CD system, not recommended for permanent installation  
- **Developer Note**: Maintained by student developers, emails checked only on Saturdays  

### Disk Layout Requirements
| Component    | Disk Location          | Size Limit     |
|--------------|------------------------|----------------|
| Bootloader   | Sector 1 (LBA 0)       | 512 bytes      |
| Kernel       | Sectors 2-255 (LBA 1-254) | Max 127.5KB |

## Features
### Implemented Commands
| Command | Description               | Example                     |
|---------|---------------------------|-----------------------------|
| `help`  | Show help information     | `help`                      |
| `clear` | Clear screen              | `clear`                     |
| `ls`    | List files                | `ls`                        |
| `cat`   | View file contents        | `cat README.TXT`            |
| `write` | Write to file             | `write test.txt "Hello"`    |
| `rm`    | Delete file               | `rm oldfile.txt`            |
| `mkdir` | Create directory          | `mkdir docs`                |
| `cd`    | Change directory          | `cd /home`                  |
| `reboot`| Reboot system             | `reboot`                    |
| `echo`  | Print text                | `echo "Hello"`              |
| `run`   | Run script                | `run test.sh`               |
| `nano`  | Text editor               | `nano file.txt`             |

## Important Notes
1. Current version is still in development, some features may be unstable  
2. Future plans include gradual optimization into a Linux-like complete system  
3. Filesystem is case-sensitive  

## Contribution
### How to Contribute
- Pull Requests are welcome  
- Please ensure basic tests pass (e.g. QEMU) before submitting  

### Contact Developers
- **Email**: 15730642468@163.com
- **Response Time**:  
  - As the developer is a student, emails are only checked on Saturdays during school terms.  
  - During holidays, responses may be delayed on the first and last days of vacation.  
- **Suggested Format**: Please prefix email subject with `[TOS]`  
