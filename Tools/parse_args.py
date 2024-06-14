import argparse
parser = argparse.ArgumentParser(description='Tools For Arguments',
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument(
    "--dataset",
    type=str,
    default='ImageMagick',
    help="Choose dataset name",
)
parser.add_argument(
    "--parsepool",
    type=str,
    default='True',
    help="choose if parse pool",
)

args = parser.parse_args()