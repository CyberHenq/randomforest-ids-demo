"""flow.py saves the information of a single traffic flow."""

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

import statistics

from cicids_rforest.flow.flow_features import FlowFeatures

THRESHOLD = 5

class Flow:
    """
    Describes a single traffic flow.
    """

    def __init__(self, packet):
        self.packetInfos = [packet]
        self.fwdPacketInfos = [packet]
        self.bwdPacketInfos = []

        self.flowFeatures = FlowFeatures()
        self.flowFeatures.setDestPort(packet.getDestPort())

        self.flowFeatures.setFwdPSHFlags(0 if not packet.getURGFlag() else 1)
        self.flowFeatures.setMinPacketLen(packet.getPayloadBytes())
        self.flowFeatures.setMaxPacketLen(packet.getPayloadBytes())
        self.flowFeatures.setPacketLenMean(packet.getPayloadBytes())
        self.flowFeatures.setFwdPacketLenMax(packet.getPayloadBytes())
        self.flowFeatures.setFwdPacketLenMin(packet.getPayloadBytes())
        self.flowFeatures.setFINFlagCount(1 if packet.getFINFlag() else 0)
        self.flowFeatures.setSYNFlagCount(1 if packet.getSYNFlag() else 0)
        self.flowFeatures.setPSHFlagCount(1 if packet.getPSHFlag() else 0)
        self.flowFeatures.setACKFlagCount(1 if packet.getACKFlag() else 0)
        self.flowFeatures.setURGFlagCount(1 if packet.getURGFlag() else 0)

        self.flowFeatures.setAvgPacketSize(packet.getPacketSize())
        self.flowFeatures.setInitBytesFwd(packet.getWinBytes())

        self.flowLastSeen = packet.getTimestamp()
        self.fwdLastSeen = packet.getTimestamp()
        self.bwdLastSeen = 0
        self.flowStartTime = packet.getTimestamp()
        self.startActiveTime = packet.getTimestamp()
        self.endActiveTime = packet.getTimestamp()

        self.flowIAT = []
        self.fwdIAT = []
        self.bwdIAT = []
        self.flowActive = []
        self.flowIdle = []

        self.packet_count = 1
        self.fwd_packet_count = 1
        self.bwd_packet_count = 0

    def getFlowStartTime(self):
        return self.flowLastSeen

    def new(self, packetInfo, direction):
        if direction == 'bwd':
            self.bwdPacketInfos.append(packetInfo)

            if self.bwd_packet_count == 0:
                self.flowFeatures.setBwdPacketLenMin(packetInfo.getPayloadBytes())
                self.flowFeatures.setInitWinBytesBwd(packetInfo.getWinBytes())
            else:
                self.flowFeatures.setBwdPacketLenMin(
                    min(self.flowFeatures.bwd_packet_len_min, packetInfo.getPayloadBytes()))
                self.bwdIAT.append((packetInfo.getTimestamp() - self.bwdLastSeen) * 1000 * 1000)

            self.bwd_packet_count = self.bwd_packet_count + 1
            self.bwdLastSeen = packetInfo.getTimestamp()

        else:
            self.fwdPacketInfos.append(packetInfo)
            self.flowFeatures.setFwdPacketLenMax(
                max(self.flowFeatures.fwd_packet_len_max, packetInfo.getPayloadBytes()))
            self.flowFeatures.setFwdPacketLenMin(
                min(self.flowFeatures.fwd_packet_len_min, packetInfo.getPayloadBytes()))
            self.fwdIAT.append((packetInfo.getTimestamp() - self.fwdLastSeen) * 1000 * 1000)
            self.flowFeatures.setFwdPSHFlags(max(1 if packetInfo.getURGFlag() else 0,
                                                 self.flowFeatures.getFwdPSHFlags()))
            self.fwd_packet_count = self.fwd_packet_count + 1
            self.fwdLastSeen = packetInfo.getTimestamp()

        self.flowFeatures.setMaxPacketLen(max(self.flowFeatures.getMaxPacketLen(), packetInfo.getPayloadBytes()))
        self.flowFeatures.setMinPacketLen(min(self.flowFeatures.getMinPacketLen(), packetInfo.getPayloadBytes()))

        if packetInfo.getFINFlag():
            self.flowFeatures.setFINFlagCount(1)
        if packetInfo.getSYNFlag():
            self.flowFeatures.setSYNFlagCount(1)
        if packetInfo.getPSHFlag():
            self.flowFeatures.setPSHFlagCount(1)
        if packetInfo.getACKFlag():
            self.flowFeatures.setACKFlagCount(1)
        if packetInfo.getURGFlag():
            self.flowFeatures.setURGFlagCount(1)

        time = packetInfo.getTimestamp()
        if time - self.endActiveTime > THRESHOLD:
            if self.endActiveTime - self.startActiveTime > 0:
                self.flowActive.append(self.endActiveTime - self.startActiveTime)
            self.flowIdle.append(time - self.endActiveTime)
            self.startActiveTime = time
            self.endActiveTime = time
        else:
            self.endActiveTime = time

        self.packet_count = self.packet_count + 1
        self.packetInfos.append(packetInfo)
        self.flowIAT.append((packetInfo.getTimestamp() - self.flowLastSeen) * 1000 * 1000)
        self.flowLastSeen = packetInfo.getTimestamp()

    def terminated(self):
        duration = (self.flowLastSeen - self.flowStartTime) * 1000 * 1000
        self.flowFeatures.setFlowDuration(duration)

        fwd_packet_lens = [x.getPayloadBytes() for x in self.fwdPacketInfos]
        bwd_packet_lens = [x.getPayloadBytes() for x in self.bwdPacketInfos]

        sum_bwd_packet_lens = sum(bwd_packet_lens)

        down_up_ratio = sum(fwd_packet_lens) / sum_bwd_packet_lens if sum_bwd_packet_lens > 0 else 1
        self.flowFeatures.setDownUpRatio(down_up_ratio)

        if len(bwd_packet_lens) > 0:
            self.flowFeatures.setBwdPacketLenMean(statistics.mean(bwd_packet_lens))
            self.flowFeatures.setTotalBwdPacketsLen(sum_bwd_packet_lens)
           

        if len(fwd_packet_lens) > 0:
            self.flowFeatures.setTotalFwdPacketsLen(sum(fwd_packet_lens))

        if len(self.flowIAT) > 0:
            self.flowFeatures.setFlowIATMean(statistics.mean(self.flowIAT))
            self.flowFeatures.setFlowIATMax(max(self.flowIAT))
            if len(self.flowIAT) > 1:
                self.flowFeatures.setFlowIATStd(statistics.stdev(self.flowIAT))

        if len(self.fwdIAT) > 0:
            self.flowFeatures.setFwdIATTotal(sum(self.fwdIAT))
            self.flowFeatures.setFwdIATMean(statistics.mean(self.fwdIAT))
            self.flowFeatures.setFwdIATMax(max(self.fwdIAT))
            self.flowFeatures.setFwdIATMin(min(self.fwdIAT))
            

        if len(self.bwdIAT) > 0:
            self.flowFeatures.setBwdIATTotal(sum(self.bwdIAT))
            self.flowFeatures.setBwdIATMean(statistics.mean(self.bwdIAT))
            self.flowFeatures.setBwdIATMax(max(self.bwdIAT))
            self.flowFeatures.setBwdIATMin(min(self.bwdIAT))
            

        self.flowFeatures.setFwdPackets_s(0 if duration == 0 else self.fwd_packet_count / (duration / (1000 * 1000)))

        packet_lens = [x.getPayloadBytes() for x in self.packetInfos]
        if len(packet_lens) > 0:
            self.flowFeatures.setPacketLenMean(statistics.mean(packet_lens))
            if len(packet_lens) > 1:
                self.flowFeatures.setPacketLenStd(statistics.stdev(packet_lens))
                self.flowFeatures.setPacketLenVar(statistics.variance(packet_lens))

        packet_sizes =[x.getPacketSize() for x in self.packetInfos]
        self.flowFeatures.setAvgPacketSize(sum(packet_sizes) / self.packet_count)

        if self.bwd_packet_count != 0:
            self.flowFeatures.setAvgBwdSegmentSize(sum(bwd_packet_lens) / self.bwd_packet_count)

        if len(self.flowIdle) > 0:
            self.flowFeatures.setIdleMean(statistics.mean(self.flowIdle))
            self.flowFeatures.setIdleMax(max(self.flowIdle))
            self.flowFeatures.setIdleMin(min(self.flowIdle))

        return [self.flowFeatures.getDestPort(),
                self.flowFeatures.getFlowDuration(),
                self.flowFeatures.getFwdPacketLenMax(),
                self.flowFeatures.getFwdPacketLenMin(),
                self.flowFeatures.getBwdPacketLenMin(),
                self.flowFeatures.getBwdPacketLenMean(),
                self.flowFeatures.getFlowIATMean(),
                self.flowFeatures.getFlowIATStd(),
                self.flowFeatures.getFlowIATMax(),
                self.flowFeatures.getFwdIATTotal(),
                self.flowFeatures.getFwdIATMean(),
                self.flowFeatures.getFwdIATMax(),
                self.flowFeatures.getFwdIATMin(),
                self.flowFeatures.getBwdIATTotal(),
                self.flowFeatures.getBwdIATMean(),
                self.flowFeatures.getBwdIATMax(),
                self.flowFeatures.getBwdIATMin(),
                self.flowFeatures.getFwdPSHFlags(),
                self.flowFeatures.getFwdPackets_s(),
                self.flowFeatures.getMinPacketLen(),
                self.flowFeatures.getPacketLenMean(),
                self.flowFeatures.getFINFlagCount(),
                self.flowFeatures.getSYNFlagCount(),
                self.flowFeatures.getPSHFlagCount(),
                self.flowFeatures.getACKFlagCount(),
                self.flowFeatures.getURGFlagCount(),
                #self.flowFeatures.getDownUpRatio(),
                self.flowFeatures.getAvgPacketSize(),
                self.flowFeatures.getAvgBwdSegmentSize(),
                self.flowFeatures.getInitWinBytesFwd(),
                self.flowFeatures.getInitWinBytesBwd(),
                self.flowFeatures.getIdleMean(),
                self.flowFeatures.getIdleMax(),
                self.flowFeatures.getIdleMin()
               ]
