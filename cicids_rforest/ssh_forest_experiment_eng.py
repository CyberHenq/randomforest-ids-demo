"""ssh_forest_experiment.py trains, analyses and optimizes various random forests 
using the CICIDS2017 dataset."""

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
import time

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn

from numpy import array

from sklearn import preprocessing
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler

from sklearn.feature_selection import SelectKBest
from sklearn.feature_selection import chi2

from sklearn.ensemble import RandomForestClassifier

from sklearn import metrics
from sklearn.metrics import accuracy_score
from sklearn.metrics import confusion_matrix
from sklearn.metrics import precision_recall_fscore_support as score
from sklearn.metrics import roc_auc_score
from sklearn.metrics import roc_curve

from os.path import join as path_join

from cicids_rforest.sniff_ssh import check_folders

### PREPROCESSING

# path to where ML files are stored
DATASET_PATH = 'ids-data/ssh'
IMAGES_PATH ="images-final-4"
IMAGES_FORMAT = ".png"
rng = 42 # random state for reproducing results

check_folders([DATASET_PATH, IMAGES_PATH])

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

labels = ['BENIGN', 'SSH-Patator']
label_groups = ['benign', 'brute_force']
label_map = {'BENIGN' : 'benign',
             'SSH-Patator': 'brute_force'}

def preprocess_dataset(path=DATASET_PATH, col_names=col_names):
    all_files = glob.glob(path + "/*.csv")

    # concatenate the files into 1
    dataset = pd.concat((pd.read_csv(f) for f in all_files))

    # Assign the column names
    dataset.columns = col_names
    # Peak at first 5 records in the dataset
    dataset.head(5)

    # get statistics about each feature
    with pd.option_context('display.max_rows', None, 'display.max_columns', None, 'display.width', 100):
        print(dataset.describe().transpose().to_string())

    # check all the values are numerical
    # if not, would have to encode
        print(dataset.dtypes)

    dataset['Flow_Bytes_s'] = dataset['Flow_Bytes_s'].astype('float64')
    dataset['Flow_Packets_s'] = dataset['Flow_Packets_s'].astype('float64')
    dataset = dataset.loc[:, ~dataset.columns.duplicated()]

    print("{} {}".format("Dataset null values check: ", dataset.isnull().any().any()))

    # Replace Inf values with NaN
    dataset = dataset.replace([np.inf, -np.inf], np.nan)
    # Drop all occurences of NaN
    dataset = dataset.dropna()

    print("{} {}".format("Dataset null values double check: ", dataset.isnull().any().any()))

    # Distribution of Dataset
    print("Dataset distribution:")
    print(dataset['Label'].value_counts())

    dataset = dataset.dropna()
    dataset['Label'].value_counts()

    # Create attack column, containing binary labels
    dataset['Attack'] = np.where(dataset['Label'] == 'BENIGN', 0, 1)

    # Proposed Groupings

    # Create grouped label column
    dataset['Label_Category'] = dataset['Label'].map(lambda x: label_map[x])
    dataset['Label_Category'].value_counts()

    return dataset


## SPLIT DATA

def split_dataset(dataset):
    # 3 Different labeling options
    label_columns = ['Label', 'Label_Category', 'Attack']

    # xs=feature vectors, ys=labels
    xs = dataset.drop(label_columns, axis=1)
    ys = dataset[label_columns]

    # Split data using 60:20:20 ratio, for training, test and validation dataset.
    # Stratify the subsets so that the proportions of attacks remain the same for all of them.
    x_train, x_temp, y_train, y_temp = train_test_split(xs, ys, test_size=0.4, random_state=0, stratify=ys['Label'])
    x_test, x_validate, y_test, y_validate = train_test_split(x_temp, y_temp, test_size=0.5, random_state=0, stratify=y_temp['Label'])

    column_names = np.array(list(x_train))
    to_drop = []
    for x in column_names:
        size = x_train.groupby([x]).size()
        # check for columns that only take one value
        if (len(size.unique()) == 1):
            to_drop.append(x)
    print("{} {}".format("Redundant columns to drop: ", to_drop))

    # Drop redundant columns
    x_train = x_train.drop(to_drop, axis=1)
    x_test = x_test.drop(to_drop, axis=1)
    x_validate = x_validate.drop(to_drop, axis=1)
    dataset = dataset.drop(to_drop, axis=1)

    print("{} {} {}".format(len(dataset.columns), " Dataset columns after drop: ", dataset.columns))

    return x_train, x_validate, x_test, y_train, y_validate, y_test, dataset

## APPLY NORMALISATION

def normalize_dataset(x_train, x_validate, x_test):
    # Normalise
    min_max_scaler = MinMaxScaler(feature_range=(0,1)).fit(x_train)

    # Apply normalisation to dataset
    x_train = min_max_scaler.transform(x_train)
    x_validate = min_max_scaler.transform(x_validate)
    x_test = min_max_scaler.transform(x_test)

    return x_train, x_validate, x_test


## FEATURE SELECTION
def feature_selection(x_train, x_validate, x_test, y_train, dataset):
    features = SelectKBest(score_func=chi2, k=x_train.shape[1])

    #fit features to the training dataset
    fit = features.fit(x_train, y_train.Label)

    # plot the score associated with each feature
    print("{} {} {}".format(len(dataset.columns), " Dataset columns: ", dataset.columns))
    print("{} {} {}".format(len(features.scores_), " Features scores: ", features.scores_))

    x = np.arange(len(dataset.columns[:-3]))  # the label locations on plot
    bar_width = 0.35

    fig, ax = plt.subplots(1)

    rects1 = ax.bar([i for i in range(len(features.scores_))], features.scores_, bar_width)
    ax.set_ylabel('Feature score')
    ax.set_title('Features comparison')
    ax.set_xticks(x)
    plt.setp(ax.get_xticklabels(), rotation=90, horizontalalignment='center')
    ax.set_xticklabels(dataset.columns[:-3])

    ax.bar_label(rects1, padding=3, rotation=90, fontsize=5)
    plt.ylim(0, 5000)

    fig.tight_layout()
    fig.set_figwidth(15)
    fig.set_figheight(5)

    plt.savefig(path_join(IMAGES_PATH, 'features' + IMAGES_FORMAT), dpi=300)
    plt.clf()

    # sort the features by importance score
    feature_importances = zip(dataset.columns, features.scores_)
    feature_importances = sorted(feature_importances, key = lambda x: x[1], reverse = True)
    sorted_importances = [importance[1] for importance in feature_importances]
    sorted_features = [importance[0] for importance in feature_importances]

    x_values = list(range(len(feature_importances)))

    # plot the cumulative scores
    cumulative_importances = np.cumsum(sorted_importances)

    print("{} {}".format("sorted_importances: ", sorted_importances))
    print("{} {}".format("cumulative_importances: ", cumulative_importances))

    # Draw line at 99% of importance retained
    value99 = cumulative_importances[-1]*0.99
    selected_features_count = features.k

    for index, value in enumerate(cumulative_importances):
        if (value > value99):
            selected_features_count = index
            break

    print("{} {}".format("99 percent importance: ", value99))
    print("{} {}".format("sorted features: ", sorted_features))

    fig, ax = plt.subplots(1)
    plt.hlines(y = value99, xmin=0, xmax=len(sorted_importances), color = 'r', linestyles = 'dashed', label="99% kynnys")
    plt.xticks(x_values, sorted_features, rotation = 'vertical', fontsize=5)

    plt.plot(x_values, cumulative_importances)
    plt.xlabel('Feature', fontsize=8)
    plt.ylabel('Feature score', fontsize=8)
    plt.title('Cumulative Feature Scores', fontsize=8)
    plt.tight_layout()
    fig.set_figwidth(15)
    fig.set_figheight(5)
    plt.legend(loc="lower right")
    plt.savefig(path_join(IMAGES_PATH, 'cumulative_features' + IMAGES_FORMAT), dpi=300)
    plt.clf()

    features = SelectKBest(score_func=chi2, k=selected_features_count)
    fit = features.fit(x_train, y_train.Label)
    x_train = fit.transform(x_train)
    x_test = fit.transform(x_test)
    x_validate = fit.transform(x_validate)

    new_features = dataset.columns[features.get_support(indices=True)]

    print("{} {}".format("New features: ", new_features))

    return selected_features_count

### RANDOM FOREST ALL LABELS

def random_forest_all_labels(x_train, x_validate, y_train, y_validate):
    print("Training random forest with all labels!")
    classifier =  RandomForestClassifier(n_jobs=-1, random_state=rng)

    #fit
    start = time.time()
    classifier.fit(x_train, y_train.Label)
    end = time.time()
    training_time = end - start

    # predict
    start = time.time()
    y_predicted = classifier.predict(x_validate)
    end = time.time()
    predict_time = end  - start
    print("{} {} {} {}".format("All labels training time: ", training_time,
        " testing time: ", predict_time))

    confusion = pd.crosstab(y_predicted, y_validate.Label)
    print("RF all labels confusion matrix:")
    reverse_confusion = confusion.iloc[::-1]
    reverse_confusion = reverse_confusion.iloc[:, ::-1]
    print(reverse_confusion)

    precision, recall, fscore, support = score(y_validate.Label, y_predicted)
    d = {'attack': labels, 'precision': precision, 'recall' : recall, 'fscore': fscore}
    results = pd.DataFrame(data=d)
    print(results)
   
    accuracy = accuracy_score(y_validate.Label, y_predicted)
    print("{} {}".format("RF all labels accuracy: ", accuracy))

## RANDOM FOREST GROUPED LABELS

def random_forest_grouped_labels(x_train, x_validate, y_train, y_validate):
    classifier =  RandomForestClassifier(n_jobs=-1, random_state=rng)

    # fit
    start = time.time()
    classifier.fit(x_train, y_train.Label_Category)
    end = time.time()
    training_time = end - start

    # predict
    start = time.time()
    y_predicted = classifier.predict(x_validate)
    end = time.time()
    predict_time = end  - start
    print("{} {} {} {}".format("Grouped labels training time: ", training_time,
        " testing time: ", predict_time))

    confusion = pd.crosstab(y_predicted, y_validate.Label_Category)
    print("RF grouped labels confusion matrix:")
    reverse_confusion = confusion.iloc[::-1]
    reverse_confusion = reverse_confusion.iloc[:, ::-1]
    print(reverse_confusion)


    precision, recall, fscore, support = score(y_validate.Label_Category, y_predicted)
    d = {'attack': label_groups, 'precision': precision, 'recall' : recall, 'fscore': fscore}
    results = pd.DataFrame(data=d)
    print(results)

    accuracy = accuracy_score(y_validate.Label_Category, y_predicted)
    print("{} {}".format("RF grouped labels accuracy: ", accuracy))


## RANDOM FOREST BINARY LABELS

def random_forest_binary_labels(x_train, x_validate, y_train, y_validate):
    classifier =  RandomForestClassifier(n_jobs=-1, random_state=rng)

    # fit
    start = time.time()
    classifier.fit(x_train, y_train.Attack)
    end = time.time()
    training_time = end - start

    # predict
    start = time.time()
    y_predicted = classifier.predict(x_validate)
    end = time.time()
    predict_time = end  - start
    print("{} {} {} {}".format("Binary labels training time: ", training_time,
        " testing time: ", predict_time))

    confusion = pd.crosstab(y_predicted, y_validate.Attack)
    print("RF binary labels confusion matrix:")
    reverse_confusion = confusion.iloc[::-1]
    reverse_confusion = reverse_confusion.iloc[:, ::-1]
    print(reverse_confusion)

    precision, recall, fscore, support = score(y_validate.Attack, y_predicted)
    d = {'attack': [0,1], 'precision': precision, 'recall' : recall, 'fscore': fscore}
    results = pd.DataFrame(data=d)
    print(results)
 
    accuracy = accuracy_score(y_validate.Attack, y_predicted)
    print("{} {}".format("RF binary labels accuracy: ", accuracy))

## OPTIMIZING

def optimize_model(x_train, x_validate, y_train, y_validate, features_count):
    
    # n estimators is the number of decision trees in the ensemble
    #n_estimators = [5, 10, 15, 20, 25, 50, 100, 200, 400, 800, 1000, 1200, 1400, 1600] # first broader search
    n_estimators = np.arange(start=1, stop=31, step=1)  # more precise search based on the results of the first search

    results = []
    time_results = []
    # note: takes a long time
    for estimator in n_estimators:
        # fit model with n_estimators parameter
        print("{} {}".format("Currently fitting estimator: ", estimator))
        classifier = RandomForestClassifier(n_estimators=estimator, n_jobs=-1, random_state=rng)
        classifier.fit(x_train, y_train.Label_Category)

        # predict validation
        start = time.time()
        y_pred = classifier.predict(x_validate)
        end = time.time()

        # calculate metrics
        p, r, f1, n = score(y_validate.Label_Category, y_pred, average = 'macro')

        # append f1 and time to results array
        results.append(f1)
        time_results.append(end-start)

    # plot classification time for n_estimators
    plt.plot(n_estimators, time_results)
    plt.xlabel('Amount of decision trees')
    plt.ylabel('Classification time (s)')
    plt.title('How the amount of decision trees changes classification time')

    plt.savefig(path_join(IMAGES_PATH, 'n_estimators-time-30' + IMAGES_FORMAT))
    plt.clf()

    combined_estimator_results = dict(zip(n_estimators, results))
    print("{} {}".format("estimator results: ", combined_estimator_results))

    # plot f1 score for n estimators
    plt.plot(n_estimators, results)
    plt.xlabel('Amount of decision trees')
    plt.ylabel('F1 Score')
    plt.title('How the amount of decision trees changes F1 score')

    plt.savefig(path_join(IMAGES_PATH, 'n_estimators-30' + IMAGES_FORMAT))
    plt.clf()

    from sklearn.model_selection import RandomizedSearchCV

    print("{} {}".format("features count: ", features_count))
   
    max_features = np.arange(start=2, stop=(features_count+1), step=1)

    print("{} {}".format("max_features: ", max_features))

    max_depth = np.arange(start=10, stop=500, step=20)
    max_depth = np.append(max_depth, None) # also have option for no max depth
    min_samples_split = [2, 5, 10]
    min_samples_leaf = [1, 2, 4]
    bootstrap = [True, False]

    random_grid = {'n_estimators': [10, 11, 12, 13, 14, 15], # chosen estimators for optimization
                   'max_features': max_features,
                   'max_depth': max_depth,
                   'min_samples_split': min_samples_split,
                   'min_samples_leaf': min_samples_leaf,
                   'bootstrap': bootstrap}

    # Use the random grid to search for best hyperparameters
    print("RF hyperparameter search")
    rf = RandomForestClassifier(n_jobs=-1, random_state=rng)

    # iter = 10, cv = 10, using StratifiedKFold because of imbalanced dataset
    # Use higher iter if you want to trade computation time for better accuracy.
    rf_random = RandomizedSearchCV(estimator = rf, param_distributions = random_grid, n_iter = 10, cv = 5, verbose=2, random_state=rng, n_jobs = -1)
    print("{} {}".format("Random grid: ", random_grid))
    rf_random.fit(x_train, y_train['Label_Category'])

    print("Hyperparameter search results:")
    print("Best parameters:")
    print(rf_random.best_params_)
    print("Best estimator:")
    print(rf_random.best_estimator_)
    print("Best score:")
    print(rf_random.best_score_)

    # Test with validation dataset

    print("RF validation")
    classifier =  rf_random.best_estimator_
    # fit
    start = time.time()
    classifier.fit(x_train, y_train.Label_Category)
    end = time.time()
    training_time = end - start

    # predict
    start = time.time()
    y_predicted = classifier.predict(x_validate)
    end = time.time()
    predict_time = end  - start
    print(training_time, predict_time)

    confusion = pd.crosstab(y_predicted, y_validate.Label_Category)
    print("Hyperparameter search confusion matrix:")
    reverse_confusion = confusion.iloc[::-1]
    reverse_confusion = reverse_confusion.iloc[:, ::-1]
    print(reverse_confusion)

    precision, recall, fscore, support = score(y_validate.Label_Category, y_predicted)
    d = {'attack': labels, 'precision': precision, 'recall' : recall, 'fscore': fscore}
    results = pd.DataFrame(data=d)
    print(results)

    accuracy = accuracy_score(y_validate.Label_Category, y_predicted)
    print("{} {}".format("RF hyperparameter search accuracy: ", accuracy))

def optimized_random_forest(x_train, x_test, y_train, y_test):
    print("Training Optimized Random Forest!")
    # chosen hyperparameters
    optimized_max_features = 26
    classifier =  RandomForestClassifier(n_estimators=14,       #12
                                         max_depth=110,         #200
                                         min_samples_split=2,   #2
                                         min_samples_leaf=2,    #1
                                         max_features=optimized_max_features,
                                         bootstrap=False,       #True
                                         n_jobs=-1,
                                         random_state=rng
    )

    # fit
    start = time.time()
    classifier.fit(x_train, y_train.Label_Category)
    end = time.time()
    training_time = end - start

    # predict
    start = time.time()
    y_predicted = classifier.predict(x_test)
    end = time.time()
    predict_time = end  - start
    print("{} {:.2f} {} {:.2f}".format("training time:", training_time, " predict time: ", predict_time))

    # metrics
    confusion = pd.crosstab(y_predicted, y_test.Label_Category)
    reverse_confusion = confusion.iloc[::-1]
    reverse_confusion = reverse_confusion.iloc[:, ::-1]
    print(reverse_confusion)

    # plot heat map confusion matrix
    seaborn.set(font_scale=1.4)
    ax = seaborn.heatmap(reverse_confusion, annot=True, annot_kws={"size": 12}, fmt='g', yticklabels="auto")

    plt.xlabel('Actual')
    plt.ylabel('Predicted')
    plt.title('Confusion matrix for final results')
  
    plt.savefig(path_join(IMAGES_PATH, 'confusion_matrix' + IMAGES_FORMAT))
    plt.clf()

    precision, recall, fscore, support = score(y_test.Label_Category, y_predicted)
  
    d = {'attack': labels, 'precision': precision, 'recall' : recall, 'fscore': fscore}
    results = pd.DataFrame(data=d)

    accuracy = accuracy_score(y_test.Label_Category, y_predicted)  

    print(results)

    pred_unique, pred_counts = np.unique(y_predicted, return_counts=True)
    test_unique, test_counts = np.unique(y_test.Label_Category, return_counts=True)
    pred_dict = dict(zip(pred_unique, pred_counts))
    test_dict = dict(zip(test_unique, test_counts))
    print("{} {}".format("test set classification counts: ", test_dict))

    print("{} {}".format("prediction counts: ", pred_dict))
    print("{} {}".format("Model accuracy: ", accuracy))

    print(y_train['Label_Category'].value_counts()/len(y_train)*100)


def main():
    dataset = preprocess_dataset(DATASET_PATH, col_names)
    x_train, x_validate, x_test, y_train, y_validate, y_test, dataset = split_dataset(dataset)
    x_train, x_validate, x_test = normalize_dataset(x_train, x_validate, x_test)
    features_count = feature_selection(x_train, x_validate, x_test, y_train, dataset)
    random_forest_all_labels(x_train, x_validate, y_train, y_validate)
    random_forest_grouped_labels(x_train, x_validate, y_train, y_validate)
    random_forest_binary_labels(x_train, x_validate, y_train, y_validate)
    optimize_model(x_train, x_test, y_train, y_test, features_count)
    optimized_random_forest(x_train, x_test, y_train, y_test)

if __name__ == '__main__':
    main()
