import argparse

from clientmod import *
        
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Client settings")
    parser.add_argument("--nocon", default=False, type=bool)
    args = vars(parser.parse_args())
    connect = not args["nocon"]
    
    root = tk.Tk()
    client = Client(root, connect)
    
    root.mainloop()
