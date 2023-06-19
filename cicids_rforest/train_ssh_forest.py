"""train_ssh_forest.py trains optimized random forest for traffic classification purposes using the CICIDS2017 dataset."""

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


# import required libraries 
import glob
import numpy as np
import pandas as pd
import time

from numpy import array
from sklearn.preprocessing import MinMaxScaler
from sklearn.ensemble import RandomForestClassifier



def train(path):
  # PREPROCESSING

  # path to where dataset csv files are stored
  all_files = glob.glob(path + "/*.csv")

  # concatenate the files into 1
  dataset = pd.concat((pd.read_csv(f, low_memory=False) for f in all_files))

  col_names = ["Destination_Port",
               "Flow_Duration",
               "Total_Fwd_Packets",
               "Total_Backward_Packets",
               "Total_Length_of_Fwd_Packets",
               "Total_Length_of_Bwd_Packets",
               "Fwd_Packet_Length_Max",
               "Fwd_Packet_Length_Min",
               "Fwd_Packet_Length_Mean",
               "Fwd_Packet_Length_Std",
               "Bwd_Packet_Length_Max",
               "Bwd_Packet_Length_Min",
               "Bwd_Packet_Length_Mean",
               "Bwd_Packet_Length_Std",
               "Flow_Bytes_s",
               "Flow_Packets_s",
               "Flow_IAT_Mean",
               "Flow_IAT_Std",
               "Flow_IAT_Max",
               "Flow_IAT_Min",
               "Fwd_IAT_Total",
               "Fwd_IAT_Mean",
               "Fwd_IAT_Std",
               "Fwd_IAT_Max",
               "Fwd_IAT_Min",
               "Bwd_IAT_Total",
               "Bwd_IAT_Mean",
               "Bwd_IAT_Std",
               "Bwd_IAT_Max",
               "Bwd_IAT_Min",
               "Fwd_PSH_Flags",
               "Bwd_PSH_Flags",
               "Fwd_URG_Flags",
               "Bwd_URG_Flags",
               "Fwd_Header_Length",
               "Bwd_Header_Length",
               "Fwd_Packets_s",
               "Bwd_Packets_s",
               "Min_Packet_Length",
               "Max_Packet_Length",
               "Packet_Length_Mean",
               "Packet_Length_Std",
               "Packet_Length_Variance",
               "FIN_Flag_Count",
               "SYN_Flag_Count",
               "RST_Flag_Count",
               "PSH_Flag_Count",
               "ACK_Flag_Count",
               "URG_Flag_Count",
               "CWE_Flag_Count",
               "ECE_Flag_Count",
               "Down_Up_Ratio",
               "Average_Packet_Size",
               "Avg_Fwd_Segment_Size",
               "Avg_Bwd_Segment_Size",
               "Fwd_Header_Length",
               "Fwd_Avg_Bytes_Bulk",
               "Fwd_Avg_Packets_Bulk",
               "Fwd_Avg_Bulk_Rate",
               "Bwd_Avg_Bytes_Bulk",
               "Bwd_Avg_Packets_Bulk",
               "Bwd_Avg_Bulk_Rate",
               "Subflow_Fwd_Packets",
               "Subflow_Fwd_Bytes",
               "Subflow_Bwd_Packets",
               "Subflow_Bwd_Bytes",
               "Init_Win_bytes_forward",
               "Init_Win_bytes_backward",
               "act_data_pkt_fwd",
               "min_seg_size_forward",
               "Active_Mean",
               "Active_Std",
               "Active_Max",
               "Active_Min",
               "Idle_Mean",
               "Idle_Std",
               "Idle_Max",
               "Idle_Min",
               "Label"
              ]
  
  # Assign the column names
  dataset.columns = col_names
  
  dataset['Flow_Bytes_s'] = dataset['Flow_Bytes_s'].astype('float64')
  dataset['Flow_Packets_s'] = dataset['Flow_Packets_s'].astype('float64')
  dataset = dataset.loc[:, ~dataset.columns.duplicated()]
  
  # Replace Inf values with NaN
  dataset = dataset.replace([np.inf, -np.inf], np.nan)
  # Drop all occurences of NaN
  dataset = dataset.dropna()
  
  dataset = dataset.dropna()
  dataset['Label'].value_counts()
  
  # Label Groups
  label_map = {'BENIGN' : 'benign', 
             'SSH-Patator': 'brute_force'}

  # Create grouped label column
  dataset['Label'] = dataset['Label'].map(lambda x: label_map[x])
  
  label_columns = ['Label']
  chosen_features = ['Destination_Port',
                     'Flow_Duration',
                     'Fwd_Packet_Length_Max',
                     'Fwd_Packet_Length_Min',
                     'Bwd_Packet_Length_Min',
                     'Bwd_Packet_Length_Mean',
                     'Flow_IAT_Mean',
                     'Flow_IAT_Std',
                     'Flow_IAT_Max',
                     'Fwd_IAT_Total',
                     'Fwd_IAT_Mean',
                     'Fwd_IAT_Max',
                     'Fwd_IAT_Min',
                     'Bwd_IAT_Total',
                     'Bwd_IAT_Mean',
                     'Bwd_IAT_Max',
                     'Bwd_IAT_Min',
                     'Fwd_PSH_Flags',
                     'Fwd_Packets_s',
                     'Min_Packet_Length',
                     'Packet_Length_Mean',
                     'FIN_Flag_Count',
                     'SYN_Flag_Count',
                     'PSH_Flag_Count',
                     'ACK_Flag_Count',
                     'URG_Flag_Count',
                     #'Down_Up_Ratio',
                     'Average_Packet_Size',
                     'Avg_Bwd_Segment_Size',
                     'Init_Win_bytes_forward',
                     'Init_Win_bytes_backward',
                     'Idle_Mean',
                     'Idle_Max',
                     'Idle_Min'
                      ]

  xs = dataset[chosen_features]
  ys = dataset[label_columns]


  # NORMALIZATION
  print(" Transforming features using MinMaxScaler ".center(50, '~'))
  start = time.time()
  min_max_scaler = MinMaxScaler(feature_range=(0,1)).fit(xs)
  end = time.time()
  transform_time = end - start
  print("{} {}".format("Transform time: ", transform_time))

  # Apply normalization to dataset
  xs = min_max_scaler.transform(xs)
  
  optimized_max_features = 26
  classifier =  RandomForestClassifier(n_estimators=14,
                                       max_depth=110,
                                       min_samples_split=2,
                                       min_samples_leaf=2,
                                       max_features=optimized_max_features,
                                       bootstrap=False,
                                       n_jobs=-1
  )

  print(" Training RF ".center(30, '~'))
  start = time.time()
  classifier.fit(xs, ys)
  end = time.time()
  training_time = end - start

  print("{} {}".format("Training time: ", training_time))

  return min_max_scaler, classifier