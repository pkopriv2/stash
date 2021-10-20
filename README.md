# Project Iron (Fe)

Security for developers.

## Getting Started

To get started, head on over to our [Getting Started](https://dev.cott.io/docs/) site.

## Versioning

This project uses [semantic versioning](http://semver.org/), e.g.: iron-core-1.0.0.  We promise backwards compability for all minor updates beginning at iron-core-1.0.0.

## Building Source

### Windows

Windows has been tested with the Windows Subsystem for Linux (WSL), in order to enable it you must be running Windows 10 version 1607 or above. (To check version: Settings-> System -> About) If your version is less than 1607, update your windows system. WSL will only run on 64-bit versions of Windows 10. 32-bit versions are not supported.  Type 'turn windows features on and off' in the search bar. Set or select 'Windows Subsystem for Linux' option in this menu.  Once this option is selected, you have to restart the computer to enforce the new updates made.  Download Ubuntu from Microsoft store.  Once enabled you need to run WSL as Administrator.  Once you have WSL up and running update the repos (sudo apt update) to make sure that your sudo command is working correctly.  Once confirmed you can continue with the instructions in the All OSes section.

### Fe - Native Windows Installation

Install Git on Windows
http://git-scm.com/download/win

#### Prerequisites

#### Install Go

https://golang.org/dl/
Download the latest version of windows-386.msi
Format: “go.<version>.windows-386.msi”

#### Glide

Go to [glide releases](https://github.com/Masterminds/glide/releases)

Download ‘glide-<version>.windows-386.zip
Extract ‘glide.exe’ into ‘<go_root>\bin’ (generally C:\go\bin)
Use these commands to unzip the file and then move the glide.exe to the correct location.
```
PowerShell Expand-Archive -Path "C:\Users\%username%\Downloads\glide-v0.13.1-windows-386.zip" -DestinationPath "C:\Go\bin"
```
```
move C:\Go\bin\windows-386\glide.exe C:\Go\bin
```

#### Cloning iron-core to local directory

Create the following directory with inside the Windows Terminal.
```
mkdir %userprofile%\go\src\github.com\cott-io
```
Clone ‘iron-core’ into above directory after you have the privileges to ‘cott-io/iron-core’ repository in github.
Navigate to above directory 
```
cd %userprofile%\go\src\github.com\cott-io
```
cmd command: 
```
git clone https://github.com/cott-io/iron-core
```

#### Install Project Dependencies

Move to the iron-core directory and Type "glide install"
```
cd C:\Users\%username%\go\src\github.com\cott-io\iron-core
```
Then:
```
glide install
```
Verify the installation by typing ‘glide’ in the Windows Terminal
```
glide
```

#### Install Environment Variables

Create user variable “GOROOT”, with value - ‘%USERPROFILE%\go’
```
setx GOROOT "%USERPROFILE%\go"
```

Create user variable - “GOBIN”  with value - ‘%GOROOT%\bin’
```
setx GOBIN "%GOROOT%\bin"
```
After the environment variables are set the command prompt needs to be closed and re-opened for the path to be set.

#### Install Cygwin

Download Cygwin from ‘https://cygwin.com/install.html’
Create a new folder named ‘cygwin64’ in C:\
Cmd Command:
```
mkdir C:\cygwin64
```
Move ‘setup-x86_64.exe’ (downloaded file) to C:\cygwin64
Command Prompt Command:
```
move C:\Users\%username%\Downloads\setup-x86_64.exe C:\cygwin64 
```
Navigate to ‘C:\cygwin64’ directory
Command Prompt Command:
```
cd C:\cygwin64
```
Enter the following command:
```
setup-x86_64.exe -q -P wget -P gcc-g++ -P make -P diffutils -P libmpfr-devel -P libgmp-devel -P libmpc-devel
```

Installation help - ‘http://preshing.com/20141108/how-to-install-the-latest-gcc-on-windows/’

#### Install TDM-GCC MinGW Compiler
Download and install "tdm64-gcc-5.1.0-2.exe" from ‘https://sourceforge.net/projects/tdm-gcc/?source=typ_redirect’ and add to start menu.

#### Installation - Create: Create a new TDM-GCC installation
Go to command prompt and enter the following commands.
```
cd C:\ProgramData\Microsoft\Windows\Start Menu\Programs\TDM-GCC-64
```
```
MinGW Command Prompt
```
This will start a DOS prompt with the correct environment for using MinGW with GCC.

Within this DOS prompt window, navigate to your GOPATH. 
```
cd %GOROOT%
```
Enter the following command:
```
go get -u github.com/mattn/go-sqlite3
```
Then enter:
```
go install github.com/mattn/go-sqlite3
```


#### Build your cloned project and add the environment variable

In your command prompt, navigate to your cloned project location
C:\Users\<user>\go\src\github.com\cott-io\iron-core\cmd\fe
Build fe.go using the command

```
cd C:\Users\%username%\go\src\github.com\cott-io\iron-core\cmd\fe
go build fe.go
```

Run ‘fe’ using the command prompt.
```
fe
```

#### Troubleshooting Possible Installation Problems

cannot find -lmingwex (or) cannot find -lmingw32

Type in where gcc (or) where g++ and find out different installations of gcc.

If you find multiple versions of gcc or g++, make sure to remove references of all the different versions in environment variables except for TDM-GCC-64.

Build the project again by making sure only one instance of g++ or gcc is referenced by using where gcc again.

### All OSes
Let's start with installing our build dependencies.  First piece of software we need to install is git, from a Linux environment use your package manager to install git.

For Debian based Distros (WSL Inclded)
```
sudo apt update ; sudo apt install git
```
For Arch based Distros
```
sudo pacman -Syy git
```
For RedHat based Distros
```
yum install git
```
For Macs, download the git distribution from [git-scm](https://git-scm.com), or use brew to install git.

Next we will install Go, this will work for every OS (WSL too).  You will need to make sure you have wget installed for these commands to work.  Note :: The code is not compatible with anything other than Go 1.9 at this time.
```
wget https://dl.google.com/go/go1.9.5.linux-amd64.tar.gz
tar -C /usr/local -xvzf go1.9.5.linux-amd64.tar.gz
```
Next we need to add $GOROOT and $GOPATH/bin to our path.
```
export PATH=$PATH:/usr/local/go:~/go/bin
```
You can add the preceding line to your ~/.bashrc (if you are using bash) or ~/.zshrc (if you are using zsh), to keep the PATH to stay persistent, and not have to set it everytime you exit and re-enter the shell.  If using another shell please read your shell's documentation on where to modify it to add the export PATH variable.  If you choose to do this you should source your config so it takes immediate effect without restarting your shell.
```
source ~/.bashrc
```
Now we want to confirm that our go environment is setup properly.
```
go env
```
We want to make sure that the following is true
```
GOPATH="/home/userid/go"
GOROOT="/usr/local/go"
```
If these are not set to the right settings you can export them like you did the path.  If you have to do this it is recommended that you make these settings persistent by adding them to your appropriate rc.

Before we continue we need to make a few directories.
```
mkdir -p ~/go/{bin,src}
```
Next let's install glide.  This project uses the [glide](https://github.com/Masterminds/glide) dependency manager.  It is recommended to install glide via the official installation method.
```
curl https://glide.sh/get | sh
```
Now we are ready to checkout the iron-core source code.
```
cd ~/go/src
go get github.com/cott-io/iron-core
```
This command may fail.  If so you can git clone the repo.  If you git clone the repo you need to follow these steps.
```
cd ~/go/src
mkdir -p github.com/cott-io
cd github.com/cott-io
git clone https://github.com/cott-io/iron-core.git
```
Now we need to cd into the src directory and build the software.
```
cd ~/go/src/github.com/cott-io/iron-core
glide up
go build -v ./...
go install ./cmd/fe
```
Now confirm that you have fe installed properly.
```
fe --version
```

## Building the Server

This project uses docker to distribute its server images.

* Build:
```sh
env BUILD_REF=master ./build server.sh
```

* Run:
```sh
docker run -it -d -p 8080:8080 gcr.io/cott-io/iron-core:latest iron-server
```

## Building the Site

This project uses docker to distribute its server images.

* Build:
```sh
env BUILD_REF=master ./build site.sh
```

* Run:
```sh
docker run -it -d -p 8080:8080 gcr.io/cott-io/iron-site:latest iron-site
```
