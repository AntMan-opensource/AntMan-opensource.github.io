import os
import common
try:
    import cPickle as pickle
except ImportError:
    import pickle
originalDir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def process():
    DLDir = os.path.join(originalDir, "data", "CVEXML")
    cveDict = {}

    for xml in os.listdir(DLDir):
        subDict = common.parse_xml(os.path.join(DLDir, xml))
        cveDict.update(subDict)

    pickle.dump(cveDict, open(os.path.join(originalDir, "data", "cvedata.pkl"), "wb"))

    print "Stored " + str(len(cveDict)) + " CVE data in file 'cvedata.pkl'."


if __name__ == '__main__':
    process()
