from Event_Handler_32 import MyEventHandler
from winappdbg.win32 import *
from winappdbg import *
import sys
def simple_debugger(arg):
    # Instance a Debug object, passing it the event handler callback.
    #with Debug( MyEventHandler(), bKillOnExit = True ) as debug:
    with Debug( MyEventHandler(), bKillOnExit = True) as debug:
        try:
        # Start a new process for debugging.
            
            #debug.execv([arg], bBreakOnEntryPoint=True)
            debug.execv([arg], bFollow=True)

        # Wait for the debugee to finish.
            debug.loop()
        except:
            print sys.exc_info()[1]

    # Stop the debugger.
        finally:
            debug.stop()
 
if __name__ == '__main__':
    simple_debugger(sys.argv[1])