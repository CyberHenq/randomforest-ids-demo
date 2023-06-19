"""sniff_ssh.py captures and classifies network traffic flows to alert of SSH-Patator attacks."""

#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.

#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.

#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <https://www.gnu.org/licenses/>.


import csv
import time
import traceback

from scapy.layers.inet import TCP
from scapy.sendrecv import sniff
from scapy.interfaces import get_working_ifaces
from scapy.interfaces import show_interfaces
from scapy.interfaces import resolve_iface
from scapy.interfaces import dev_from_networkname
from scapy.interfaces import dev_from_index

from sklearn.ensemble import RandomForestClassifier
import numpy as np

from . import train_ssh_forest as ssh_forest
from cicids_rforest.flow.flow import Flow
from cicids_rforest.flow.flow_features import FlowFeatures
from cicids_rforest.flow.packet_info import PacketInfo

import warnings

from joblib import dump, load
import os
from pathlib import Path

warnings.filterwarnings("ignore")


#### Program arguments ####
dataset_csv_filepath = "ids-data/ssh"
save_model_path = "model-data/ssh-rforest.joblib"
load_model = False
classification_results_folder = "results/output_logs/malicious"
pcap_path = "pcaps/patator-cleaned.pcap"
is_live_capture = False
interface_id=None
###########################

current_flows = {}
FlowTimeout = 600

class Model:
    normalization = None
    classifier = None

    # Init function for future support of multiple models
    def __init__(self, classifier, normalization):
        self.classifier = classifier
        self.normalization = normalization

class ResultWriter():
    f = None
    w = None

    # Instance functions for future support of multiple writers
    def __init__(self, results_path):
        self.f = open(results_path, 'w')
        self.w = csv.writer(f)

    def getWriter():
        return self.w

    def closeWriter():
        self.f.close()

def classify(features, flow=None):
    # preprocess
    f = features
    features = [np.nan if x in [np.inf, -np.inf] else float(x) for x in features]

    if np.nan in features:
        return

    features = Model.normalization.transform([features])
    result = Model.classifier.predict(features)

    feature_string = [str(i) for i in f]
    classification = [str(result[0])]
    if result not in ('Benign', 'benign'):
        # Print alerts to terminal
        print("".center(50, '*'))
        print("SSH-Patator detected!")
        print(flow.packetInfos[0].getFwdID())
        print(feature_string + classification)

    ResultWriter.w.writerow(feature_string + classification)

    return feature_string + classification


def newPacket(p):
    try:
        packet = PacketInfo()
        packet.setDest(p)
        packet.setSrc(p)
        packet.setSrcPort(p)
        packet.setDestPort(p)
        packet.setProtocol(p)
        packet.setTimestamp(p)
        packet.setPSHFlag(p)
        packet.setFINFlag(p)
        packet.setSYNFlag(p)
        packet.setACKFlag(p)
        packet.setURGFlag(p)
        packet.setRSTFlag(p)
        packet.setPayloadBytes(p)
        packet.setHeaderBytes(p)
        packet.setPacketSize(p)
        packet.setWinBytes(p)
        packet.setFwdID()
        packet.setBwdID()

        if packet.getFwdID() in current_flows.keys():
            flow = current_flows[packet.getFwdID()]

            # check for timeout
            if (packet.getTimestamp() - flow.getFlowStartTime()) > FlowTimeout:
                classify(flow.terminated(), flow=flow)
                del current_flows[packet.getFwdID()]
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow

            # check for FIN flag
            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, 'fwd')
                classify(flow.terminated(), flow=flow)
                del current_flows[packet.getFwdID()]
                del flow

            else:
                flow.new(packet, 'fwd')
                current_flows[packet.getFwdID()] = flow

        elif packet.getBwdID() in current_flows.keys():
            flow = current_flows[packet.getBwdID()]

            # check for timeout
            if (packet.getTimestamp() - flow.getFlowStartTime()) > FlowTimeout:
                classify(flow.terminated(), flow=flow)
                del current_flows[packet.getBwdID()]
                del flow
                flow = Flow(packet)
                current_flows[packet.getFwdID()] = flow

            elif packet.getFINFlag() or packet.getRSTFlag():
                flow.new(packet, 'bwd')
                classify(flow.terminated(), flow=flow)
                del current_flows[packet.getBwdID()]
                del flow
            else:
                flow.new(packet, 'bwd')
                current_flows[packet.getBwdID()] = flow
        else:
            flow = Flow(packet)
            current_flows[packet.getFwdID()] = flow

    except AttributeError:
        # not IP or TCP
        return

    except:
        traceback.print_exc()


def live(selected_iface):
    print(" Begin Live Sniffing ".center(30, '~'))
    sniff(iface=selected_iface, prn=newPacket)
    for flow in current_flows.values():
        classify(flow.terminated(), flow=flow)

def pcap(f):
    print(" Begin Sniffing PCAP ".center(30, '*'))
    sniff(offline=f, prn=newPacket)
    for flow in current_flows.values():
        classify(flow.terminated(), flow=flow)

def interface_selection():
    print(" Available interfaces ".center(50, '~'))
    show_interfaces()
    iface_index_input = input("\nEnter wanted interface index: ")
    selected_iface = dev_from_index(iface_index_input)
    print(" Chosen interface ".center(50, '-'))
    print("{:<20s} {:<20s}".format("Interface name: ", selected_iface.description, " id: ", selected_iface.index, " ip: ", selected_iface.ip))
    print("{:<20s} {:<20d}".format("Interface index: ", selected_iface.index, " ip: ", selected_iface.ip))
    print("{:<20s} {:<20s}".format("Interface IP: ", selected_iface.ip))
    print("{:<20s} {:<20s}".format("Interface MAC: ", selected_iface.mac))
    print("".center(50, '-'))
    return selected_iface

def check_folders(paths):
    for path in paths:
        if os.path.exists(path):
            continue

        ext = os.path.splitext(path)[-1]

        if '.' in ext:
            folder_path = os.path.dirname(path)
            Path(folder_path).mkdir(parents=True, exist_ok=True)
        else:
            Path(path).mkdir(parents=True, exist_ok=True)

def is_valid_path(path):
    try:
        if not os.path.exists(path):
            raise FileNotFoundError
        else:
            return True
    except FileNotFoundError:
        exit("Error: file \"" + path + "\" not found")

def train_model(dataset_path, save_model_path):

    min_max_scaler, classifier = ssh_forest.train(dataset_path)
    normalization = min_max_scaler

    Model.normalization = normalization
    Model.classifier = classifier
    trained_model = {"classifier": classifier, "normalization": normalization}
    dump(trained_model, save_model_path)
    print("Model saved to: " + save_model_path)

def main(dataset_path=dataset_csv_filepath, model_path=save_model_path, load_model=load_model,
         results_folder=classification_results_folder, pcap_files=pcap_path, live_mode=is_live_capture,
         iface_id=interface_id):

    check_folders([dataset_path, model_path, results_folder])

    if load_model:
        if is_valid_path(save_model_path):
            trained_model = load(save_model_path)
            Model.classifier = trained_model['classifier']
            Model.normalization = trained_model['normalization']
            print(" Model loaded ".center(20, '*'))
    else:
        train_model(dataset_path, model_path)

    timestr = time.strftime("%d-%m-%Y_%H.%M.%S")
    classification_results_path = os.path.join(classification_results_folder, timestr + ".csv")

    ResultWriter.f = open(classification_results_path, 'w')
    ResultWriter.w = csv.writer(ResultWriter.f)

    if is_live_capture:
        if iface_id == None:
            live(interface_selection())
        else:
            live(iface_id)
    else:
        pcap(pcap_files)

    ResultWriter.f.close()

if __name__ == '__main__':
    main()