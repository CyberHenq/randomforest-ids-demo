"""flow_features.py describes the features of a traffic flow in the CICIDS2017 dataset format."""

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

class FlowFeatures:
    def __init__(self):
        self.dest_port = 0
        self.flow_duration = 0

        self.total_fwd_packets_len = 0
        self.total_bwd_packets_len = 0

        self.fwd_packet_len_max = 0
        self.fwd_packet_len_min = 0

        self.bwd_packet_len_min = 0
        self.bwd_packet_len_mean = 0

        self.flow_IAT_mean = 0  
        self.flow_IAT_std = 0   
        self.flow_IAT_max = 0   

        self.fwd_IAT_total = 0
        self.fwd_IAT_mean = 0
        self.fwd_IAT_max = 0
        self.fwd_IAT_min = 0

        self.bwd_IAT_total = 0
        self.bwd_IAT_mean = 0
        self.bwd_IAT_max = 0
        self.bwd_IAT_min = 0

        self.fwd_PSH_flags = 0

        self.fwd_packets_s = 0
        self.min_packet_len = 0
        self.max_packet_len = 0
        self.packet_len_mean = 0
        self.packet_len_std = 0
        self.packet_len_var = 0

        self.FIN_flag_count = 0
        self.SYN_flag_count = 0
        self.PSH_flag_count = 0
        self.ACK_flag_count = 0
        self.URG_flag_count = 0

        self.down_up_ratio = 0

        self.avg_packet_size = 0

        self.avg_bwd_segment_size = 0

        self.init_win_bytes_forward = -1
        self.init_win_bytes_backward = -1

        self.idle_mean = 0

        self.idle_max = 0
        self.idle_min = 0

    def getDestPort(self):
        return self.dest_port

    def setDestPort(self, value):
        self.dest_port = value

    def getFlowDuration(self):
        return self.flow_duration

    def setFlowDuration(self, value):
        self.flow_duration = int(round(value))

    def getTotalFwdPacketsLen(self):
        return self.total_fwd_packets_len

    def setTotalFwdPacketsLen(self, value):
        self.total_fwd_packets_len = value

    def getTotalBwdPacketsLen(self):
        return self.total_bwd_packets_len

    def setTotalBwdPacketsLen(self, value):
        self.total_bwd_packets_len = value

    def getFwdPacketLenMax(self):
        return self.fwd_packet_len_max

    def setFwdPacketLenMax(self, value):
        self.fwd_packet_len_max = value

    def getFwdPacketLenMin(self):
        return self.fwd_packet_len_min

    def setFwdPacketLenMin(self, value):
        self.fwd_packet_len_min = value

    def getBwdPacketLenMin(self):
        return self.bwd_packet_len_min

    def setBwdPacketLenMin(self, value):
        self.bwd_packet_len_min = value

    def getBwdPacketLenMean(self):
        return self.bwd_packet_len_mean

    def setBwdPacketLenMean(self, value):
        self.bwd_packet_len_mean = value

    def getFlowIATMean(self):
        return self.flow_IAT_mean

    def setFlowIATMean(self, value):
        self.flow_IAT_mean = int(round(value))

    def getFlowIATStd(self):
        return self.flow_IAT_std

    def setFlowIATStd(self, value):
        self.flow_IAT_std = value

    def getFlowIATMax(self):
        return self.flow_IAT_max

    def setFlowIATMax(self, value):
        self.flow_IAT_max = int(round(value))

    def getFwdIATTotal(self):
        return self.fwd_IAT_total

    def setFwdIATTotal(self, value):
        self.fwd_IAT_total = int(round(value))

    def getFwdIATMean(self):
        return self.fwd_IAT_mean

    def setFwdIATMean(self, value):
        self.fwd_IAT_mean = value

    def getFwdIATMax(self):
        return self.fwd_IAT_max

    def setFwdIATMax(self, value):
        self.fwd_IAT_max = int(round(value))

    def getFwdIATMin(self):
        return self.fwd_IAT_min

    def setFwdIATMin(self, value):
        self.fwd_IAT_min = int(round(value))

    def getBwdIATTotal(self):
        return self.bwd_IAT_total

    def setBwdIATTotal(self, value):
        self.bwd_IAT_total = int(round(value))

    def getBwdIATMean(self):
        return self.bwd_IAT_mean

    def setBwdIATMean(self, value):
        self.bwd_IAT_mean = value

    def getBwdIATMax(self):
        return self.bwd_IAT_max

    def setBwdIATMax(self, value):
        self.bwd_IAT_max = int(round(value))

    def getBwdIATMin(self):
        return self.bwd_IAT_min

    def setBwdIATMin(self, value):
        self.bwd_IAT_min = int(round(value))

    def getFwdPSHFlags(self):
        return self.fwd_PSH_flags

    def setFwdPSHFlags(self, value):
        self.fwd_PSH_flags = value

    def getFwdPackets_s(self):
        return self.fwd_packets_s

    def setFwdPackets_s(self, value):
        self.fwd_packets_s = value

    def getMaxPacketLen(self):
        return self.max_packet_len

    def setMaxPacketLen(self, value):
        self.max_packet_len = value

    def getMinPacketLen(self):
        return self.min_packet_len

    def setMinPacketLen(self, value):
        self.min_packet_len = value

    def getPacketLenMean(self):
        return self.packet_len_mean

    def setPacketLenMean(self, value):
        self.packet_len_mean = value

    def getPacketLenStd(self):
        return self.packet_len_std

    def setPacketLenStd(self, value):
        self.packet_len_std = value

    def getPacketLenVar(self):
        return self.packet_len_var

    def setPacketLenVar(self, value):
        self.packet_len_var = value

    def getFINFlagCount(self):
        return self.FIN_flag_count

    def setFINFlagCount(self, value):
        self.FIN_flag_count = value

    def getSYNFlagCount(self):
        return self.SYN_flag_count

    def setSYNFlagCount(self, value):
        self.SYN_flag_count = value

    def getPSHFlagCount(self):
        return self.PSH_flag_count

    def setPSHFlagCount(self, value):
        self.PSH_flag_count = value

    def getACKFlagCount(self):
        return self.ACK_flag_count

    def setACKFlagCount(self, value):
        self.ACK_flag_count = value

    def getURGFlagCount(self):
        return self.URG_flag_count

    def setURGFlagCount(self, value):
        self.URG_flag_count = value

    def getDownUpRatio(self):
        return self.down_up_ratio

    def setDownUpRatio(self, value):
        self.down_up_ratio = value

    def getAvgPacketSize(self):
        return self.avg_packet_size

    def setAvgPacketSize(self, value):
        self.avg_packet_size = value

    def getAvgBwdSegmentSize(self):
        return self.avg_bwd_segment_size

    def setAvgBwdSegmentSize(self, value):
        self.avg_bwd_segment_size = value

    def getInitWinBytesFwd(self):
        return self.init_win_bytes_forward

    def setInitBytesFwd(self, value):
        self.init_win_bytes_forward = value

    def getInitWinBytesBwd(self):
        return self.init_win_bytes_backward

    def setInitWinBytesBwd(self, value):
        self.init_win_bytes_backward = value

    def getIdleMean(self):
        return self.idle_mean

    def setIdleMean(self, value):
        self.idle_mean = value

    def getIdleMax(self):
        return self.idle_max

    def setIdleMax(self, value):
        self.idle_max = value

    def getIdleMin(self):
        return self.idle_min

    def setIdleMin(self, value):
        self.idle_min = value