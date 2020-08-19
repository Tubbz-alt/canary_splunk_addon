from __future__ import print_function
from solnlib.pattern import Singleton
import six


class PipeManager(six.with_metaclass(Singleton, object)):
    def __init__(self, event_writer=None):
        self._event_writer = event_writer

    def write_events(self, events):
        if not self._event_writer:
            print(events)
            return True
        return self._event_writer.write_events(events)
