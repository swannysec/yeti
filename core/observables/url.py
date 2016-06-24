from __future__ import unicode_literals

import re
import urlnorm

from core.observables import Observable
from core.observables.hostname import Hostname
from core.observables.ip import Ip
from core.errors import ObservableValidationError
from core.helpers import refang


class Url(Observable):

    regex = r"(?P<search>((?P<scheme>[\w]{2,9}):\/\/)?([\S]*\:[\S]*\@)?(?P<hostname>" + Hostname.main_regex + ")(\:[\d]{1,5})?(?P<path>(\/[\S]*)?(\?[\S]*)?(\#[\S]*)?))"

    @classmethod
    def is_valid(cls, match):
        return ((match.group('search').find('/') != -1) and
                (Hostname.check_type(match.group('hostname')) or
                 Ip.check_type(match.group('hostname'))))

    def normalize(self):
        self.value = refang(self.value)

        try:
            if re.match(r"[^:]+://", self.value) is None:  # if no schema is specified, assume http://
                self.value = u"http://{}".format(self.value)
            self.value = urlnorm.norm(self.value)
        except urlnorm.InvalidUrl:
            raise ObservableValidationError("Invalid URL: {}".format(self.value))
