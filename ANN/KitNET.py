import numpy as np
import ANN.dA as AE
import ANN.corClust as CC

# This class represents a KitNET machine learner.
# KitNET is a lightweight online anomaly detection algorithm based on an ensemble of autoencoders.
# For more information and citation, please see our NDSS'18 paper: Kitsune: An Ensemble of Autoencoders for Online Network Intrusion Detection
# For licensing information, see the end of this document

class KitNET:
    #n: the number of features in your input dataset (i.e., x \in R^n)
    #m: the maximum size of any autoencoder in the ensemble layer
    #AD_grace_period: the number of instances the network will learn from before producing anomaly scores
    #FM_grace_period: the number of instances which will be taken to learn the feature mapping. If 'None', then FM_grace_period=AM_grace_period
    #learning_rate: the default stochastic gradient descent learning rate for all autoencoders in the KitNET instance.
    #hidden_ratio: the default ratio of hidden to visible neurons. E.g., 0.75 will cause roughly a 25% compression in the hidden layer.
    #feature_map: One may optionally provide a feature map instead of learning one. The map must be a list,
    #           where the i-th entry contains a list of the feature indices to be assingned to the i-th autoencoder in the ensemble.
    #           For example, [[2,5,3],[4,0,1],[6,7]]
    def __init__(self,n,max_autoencoder_size=10,FM_grace_period=None,AD_grace_period=10000,learning_rate=0.1,hidden_ratio=0.75, feature_map = None):
        # Parameters:
        self.AD_grace_period = AD_grace_period
        if FM_grace_period is None:
            self.FM_grace_period = AD_grace_period
        else:
            self.FM_grace_period = FM_grace_period
        if max_autoencoder_size <= 0:
            self.m = 1
        else:
            self.m = max_autoencoder_size
        self.lr = learning_rate
        self.hr = hidden_ratio
        self.n = n
        self.threshold = -1

        # Variables
        self.n_trained = 0 # the number of training instances so far
        self.n_executed = 0 # the number of executed instances so far
        self.v = feature_map
        if self.v is None:
            print("\033[90mFM under training\033[0m")
        else:
            self.__createAD__()
            print("\033[90mAD under training\033[0m")
        self.FM = CC.corClust(self.n) #incremental feature cluatering for the feature mapping process
        self.ensembleLayer = []
        self.outputLayer = None

    #If FM_grace_period+AM_grace_period has passed, then this function executes KitNET on x. Otherwise, this function learns from x.
    #x: a numpy array of length n
    #Note: KitNET automatically performs 0-1 normalization on all attributes.
    def process(self,x):
        if self.n_trained > self.FM_grace_period + self.AD_grace_period: #If both the FM and AD are in execute-mode
            return self.execute(x)
        else:
            self.train(x)
            return 0.0

    #force train KitNET on x
    #returns the anomaly score of x during training (do not use for alerting)
    def train(self,x):
        if self.n_trained <= self.FM_grace_period and self.v is None: #If the FM is in train-mode, and the user has not supplied a feature mapping
            #update the incremetnal correlation matrix
            self.FM.update(x)
            if self.n_trained == self.FM_grace_period: #If the feature mapping should be instantiated
                self.v = self.FM.cluster(self.m)
                self.__createAD__()
                print("\033[90mAD under training\033[0m")
        else: #train
            ## Ensemble Layer
            S_l1 = np.zeros(len(self.ensembleLayer))
            for a in range(len(self.ensembleLayer)):
                # make sub instance for autoencoder 'a'
                xi = x[self.v[a]]
                S_l1[a] = self.ensembleLayer[a].train(xi)
            ## OutputLayer
            score = self.outputLayer.train(S_l1)
            
            # Update threshold during AD training period
            if self.n_trained > self.FM_grace_period and self.n_trained <= self.FM_grace_period + self.AD_grace_period:
                if score > self.threshold:
                    old_threshold = self.threshold
                    self.threshold = score
                    print("\033[38;5;39mThreshold updated\033[0m\n\033[90m" + f"{old_threshold:.4f} -→ {self.threshold:.4f}\033[0m")
            
            if self.n_trained == self.AD_grace_period+self.FM_grace_period:
                print("\033[90mKitNET switched to detection mode\033[0m")
        self.n_trained += 1

    #force execute KitNET on x
    def execute(self,x):
        if self.v is None:
            raise RuntimeError('\033[91mKitNET cannot analyze the features because a mapping has not yet been learned or provided 🔥\n\033[90mProvide a mapping or train the FM first\033[0m')
        else:
            self.n_executed += 1
            ## Ensemble Layer
            S_l1 = np.zeros(len(self.ensembleLayer))
            for a in range(len(self.ensembleLayer)):
                # make sub inst
                xi = x[self.v[a]]
                S_l1[a] = self.ensembleLayer[a].execute(xi)
            ## OutputLayer
            return self.outputLayer.execute(S_l1)

    def __createAD__(self):
        # construct ensemble layer
        for map in self.v:
            params = AE.dA_params(n_visible=len(map), n_hidden=0, lr=self.lr, corruption_level=0, gracePeriod=0, hiddenRatio=self.hr)
            self.ensembleLayer.append(AE.dA(params))

        # construct output layer
        params = AE.dA_params(len(self.v), n_hidden=0, lr=self.lr, corruption_level=0, gracePeriod=0, hiddenRatio=self.hr)
        self.outputLayer = AE.dA(params)