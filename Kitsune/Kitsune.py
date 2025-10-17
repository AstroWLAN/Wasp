class Kitsune:
    def __init__(self, FE, KitNET):
        # Store the provided feature extractor and anomaly detector
        self.FE = FE
        self.AnomDetector = KitNET

    # Processes the packet and computes
    def process_packet(self):
        # Computes the feature vector for the actual packet
        x, flowID = self.FE.compute_features()
        if len(x) == 0:
            return -1, None
        # Feed KitNET with the feature vector [ returns the RMSE and the flowID of the current packet ]
        return self.AnomDetector.process(x), flowID

