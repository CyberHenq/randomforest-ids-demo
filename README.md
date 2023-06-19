# :evergreen_tree: CICIDS2017-Forest :evergreen_tree:

This readme explains the steps necessary to run the code that I used for my Master's thesis. The thesis is written in Finnish so I won't share it here. Additional helpful commands are also included for those that are interested to learn more and are perhaps struggling with their own theses. This repository can also provide inspiration for future research.

:sparkles: Sharing is caring, use open source for open science! :sparkles:

:warning: DISCLAIMER: All information in this repository is for educational purposes only! Use with your own risk!

This proof of concept uses the CICIDS2017 dataset along with random forest machine learning model to detect SSH brute-force attacks.

# Install Python virtual environment & dependencies (recommended way to handle dependencies)

## Linux venv install
```bash
python3 -m venv <venv-path>
```

## Windows venv install
```bash
py -m venv <venv-path>
```

## Venv for other Python versions
```bash
pip install virtualenv
virtualenv --python=<path-to-custom-python-version>/python.exe <path>
```
Where <venv-path> can be e.g. C:/Environments/Python/myenv
and <path-to-custom-python-version> can be e.g. C:/Python/3.5.10


## Venv activation
Note that you need to activate the installed virtual environment.
Otherwise everything is run in your default operating system's shell.
You can recognize the activated virtual environment from the venv name that is included inside parentheses on the left side of your terminal prompt (usually before your username).

### Linux
```bash
source <path-to-venv>/bin/activate
```
Where <path-to-venv> is the path to the virtual environment that you created above. 

### Windows
```ps
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
<venv-path>/Scripts/activate.ps1
Set-ExecutionPolicy -ExecutionPolicy Restricted -Scope CurrentUser
```
## Install dependencies
```bash
pip install -r requirements.txt
```
Make sure that you run this command from the project's root folder or otherwise you need to correct the path to requirements.txt!

## Running easily with a shebang
The first line of every Python script is called a shebang because of the (#!) syntax. It defines the Python interpreter that should be used when attempting to run the script with bash for example. For ease of use you should point it to your created virtual environment unless you know what you are doing.
Note that you need to modify this line at least for the `run.py` script.

### Example of a shebang for run.py script
```python
#!<path-to-venv>/bin/python3

# Licensing stuff
from cicids_rforest import sniff_ssh
from cicids_rforest import train_ssh_forest
from cicids_rforest import ssh_forest_experiment_fin
import argparse, csv, getopt, glob, os, sys
from manual import print_manual

def main(argv):
# rest of the script ...
```
Where <path-to-venv> is your path to the Python shell.   
Examples of <path-to-venv>:
- Linux: /home/myuser/Environments/Python/myenv
- Windows: C:/Environments/Python/myenv

Note that on Windows you need to replace /bin/python3 with `/Scripts/python.exe`

#### Running the demo with the shebang set
Run the following command from the root project folder for random forest testing, optimization and evaluation (can take a long time):
```bash
./run.py --experiment
```

To use the classification capabilities for pcap files or raw live traffic run the command:
 ```bash
./run.py --sniff
```

## Running the demo without a shebang
Run the following command from the root project folder for random forest testing, optimization and evaluation (can take a long time):
```bash
python run.py --experiment
```

To use the classification capabilities for pcap files or raw live traffic run the command:
 ```bash
python run.py --sniff
```

# Extra notes for the demo
## Dataset
`ids-data/ssh` folder contains a subset of the CICIDS2017 dataset. This subset includes only the records necessary to learn to classify SSH-Patator attacks.
If you want to use the full CICIDS2017 dataset download it from: [https://www.unb.ca/cic/datasets/ids-2017.html](https://www.unb.ca/cic/datasets/ids-2017.html) and then place its csv files inside the `ids-data/MachineLearningCVE-Full` folder.
Also remember to replace the path from the necessary scripts (`cicids_rforest/ssh_forest_experiment.py` and `cicids_rforest/sniff_ssh.py`).

## Results & models
When you run the experiment to test and analyse the random forest, the program produces images under `images` folder.
Also when you run the sniffer to classify pcap-files or live traffic the program saves the model to `model-data` folder.
This behavior can be modified from the `cicids_rforest/sniff_ssh.py` script. The script contains useful program arguments such as `save_model_path`, 
`load_model`, `classification_results_folder`, `pcap_path` and `is_live_capture`. These might be made modifiable from the terminal in the future.

## Future development
I plan to continue my personal research on this topic after my graduation.
I might update this repo or not, only time will show.
Personally, I find the topic interesting but all the cool things weren't possible to implement within the limits of my Master's thesis.
Keep those things in mind if you need to contact me. 

I appreciete well-thought-out ideas, feedback, requests, offers, etc.


# Zeek IDS
:warning: Note: Zeek isn't necessary for the demo! You can capture network traffic with `tcpdump`, `tshark`, etc. on any system that supports them.
[Libpcap](https://www.tcpdump.org/) is the library that almost every network capturing tool is based on.
However, Zeek has it's own tricks to do forensics on network traffic so it's worth checking out!
Unfortunately, I didn't have enough time to make Zeek a bigger part of this demo.

## Installing on Deb-based (Ubuntu, Kali Linux, etc.) / Debian systems
```bash
# Install required dependencies
sudo apt-get install cmake make gcc g++ flex bison libpcap-dev libssl-dev python3 python3-dev swig zlib1g-dev
```

```bash
# Add zeek commands to your user's path.
export PATH="/opt/zeek/bin:$PATH"
```

Source: https://docs.zeek.org/en/current/install.html

## Configuration
`$PREFIX` stands for `/opt/zeek/`

Configure your interface in $PREFIX/etc/node.cf

Example config:
```
[zeek]
type=standalone
host=localhost
interface=eth0   # change this according to your listening interface in ifconfig. On Debian you can use "ip addr" command to see your interface.
```

Also remember to configure `$PREFIX/etc/networks.cfg`
Examples should be included in the file.

You should also check `$PREFIX/etc/zeekctl.cfg` but it's not always necessary.

Finish installation by running as root:
```bash
zeekctl install
```

Then you can run `zeekctl` again and enter `start` in the ZeekControl shell to start up Zeek instance.

Other useful commands are `deploy`, `check` and `diag`.

Source: https://docs.zeek.org/en/current/quickstart.html#managing-zeek-with-zeekcontrol


# CUDA headache (fortunately not needed for this project but I documented it anyway, hopefully it helps someone)
On the beginning of this project I thought that I would use Tensorflow for the practical part of my thesis which is why this documentation was created.
Gladly, scikit-learn does the job so you can ignore this part if you don't want to dive into the world of Tensorflow.

## Windows install guide
https://www.tensorflow.org/install/gpu
https://docs.nvidia.com/cuda/cuda-quick-start-guide/index.html#windows
https://docs.nvidia.com/cuda/cuda-installation-guide-microsoft-windows/
https://docs.nvidia.com/deeplearning/cudnn/install-guide/index.html#install-windows

https://developer.nvidia.com/cuda-gpus      <--- Verify if your GPU is supported
https://towardsdatascience.com/setting-up-tensorflow-on-windows-gpu-492d1120414c

- Remember to set your system PATHs!
- TensorRT doesn't work with Python on Windows so don't bother getting it according to https://docs.nvidia.com/deeplearning/tensorrt/install-guide/index.html


Downloads:
- **verify required versions from https://www.tensorflow.org/install/gpu** Latest CUDA version might work with the latest tensorflow version even if it's not yet documented, at least that was my case. 
- CUDA 11.2 is confirmed for Windows 10 with tensorflow 2.5.0.
https://developer.nvidia.com/rdp/cudnn-download
https://developer.nvidia.com/cuda-downloads?target_os=Windows&target_arch=x86_64&target_version=10&target_type=exenetwork

## Benchmarks
Running the nbody sample from CUDA:
- Gtx 1080Ti & Gtx 1070: 55.4 GFLOP/s (56.2 with cuddn)
- Gtx 1070: 29.3 GFLOP/s
- Gtx 1080Ti: 36.1 GFLOP/s
- i7 8700K: 0.41 GFLOP/s


# Miscellaneous commands
## SSH bruteforce attack with Kali Linux (for generating test traffic)
patator ssh_login host=192.168.1.2 user=FILE0 \ 
password=FILE1 0=test-users.txt 1=test-passwords.txt \
-x ignore:mesg="Authentication failed."
 
tcpdump -i eth0 -n -s 0 -B 4096 -G 30 -W 1 -w \

python run.py --experiment

python run.py --sniff

## Sed tips
### Data reduction example (removes all lines not ending with "BENIGN"): 
```bash
sed -i '/BENIGN/!d' <filename>
```

#### More advanced data reduction example (removes all lines not ending with "BENIGN" and also ignores the first line): 
```bash
sed -i '2,${/BENIGN/!d}' <filename>
```
#### Replace <filename> with a path to the wanted file e.g. ./ids-data/ssh/Monday-BENIGN.csv

### Reduce all CICIDS-2017 csv-files to contain only 1000 records, run the command from the csv-files folder: 
```bash
sed -i '1002,$d' ./*.csv
```

## Image conversion tips, useful for getting LaTeX friendly images! 
### Convert images to pdf format using img2pdf pip package:
```bash
img2pdf input.jpg -o output.pdf
```

### Scrape images from pdf files with xpdf tool:
```bash
pdfimages.exe -f <first-page> -l <last-page> -j '<source-path>' '<results-path>'
```

# References
See cicids_rforest/README.md for the references that affected the creation of the code under the cicids_rforest folder.
Special thanks go to GitHub user kyralmozley (https://github.com/kyralmozley) for making the original version of the random forest proof of concept.