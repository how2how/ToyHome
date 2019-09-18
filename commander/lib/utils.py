import ConfigParser


def load_config(path):
    cf = ConfigParser.ConfigParser()
    try:
        cf.read(path)
    except Exception as e:
        print(e)

    # sections = cf.sections()
    return cf._dict
