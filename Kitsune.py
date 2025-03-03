from ANN.KitNET import KitNET
from FeatureExtractor import *

class Kitsune:
    def __init__(self,file_path,limit,max_autoencoder_size=10,FM_grace_period=None,AD_grace_period=10000,learning_rate=0.1,hidden_ratio=0.75,):
        # Initializes the feature extractor [ based on AfterImage]
        self.FE = FE(file_path,limit)
        # Initializes the KitNET anomaly detector [ traing will happen during the grace periods ]
        self.AnomDetector = KitNET(self.FE.get_num_features(),max_autoencoder_size,FM_grace_period,AD_grace_period,learning_rate,hidden_ratio)

    # Processes the packet and computes
    def process_packet(self):
        # Computes the feature vector for the actual packet
        x = self.FE.compute_features()
        if len(x) == 0:
            return -1
        # Feed KitNET with the feature vector
        return self.AnomDetector.process(x) 

