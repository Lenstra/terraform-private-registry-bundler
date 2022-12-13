# Terraform Private Registry Builder

## Package

```bash
shiv -o tprb -p "/usr/bin/env python3" -r requirements.txt --site-packages src -e tprb:main
```

## Usage

```bash
./tprb bundle --providers hashicorp/vault --platforms linux/amd64 windows/amd64 --last-releases-only
```

### List of platforms

* darwin/amd64
* darwin/arm64
* freebsd/386
* freebsd/amd64
* freebsd/arm
* linux/386
* linux/amd64
* linux/arm
* linux/arm64
* windows/386
* windows/amd64