import ctypes

class VirtualMachine(object):
    def __init__(self, mem_size: int):
        self.void_ptr_inst = 0
