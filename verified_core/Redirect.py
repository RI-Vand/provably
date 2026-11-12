import sys
from typing import Callable, Any, TypeVar, NamedTuple
from math import floor
from itertools import count

import module_ as module_
import _dafny as _dafny
import System_ as System_
import PathTrav as PathTrav

# Module: Redirect

class default__:
    def  __init__(self):
        pass

    @staticmethod
    def Ctl(c):
        return (ord(c)) < (32)

    @staticmethod
    def Bad(u):
        def lambda0_(exists_var_0_):
            d_0_i_: int = exists_var_0_
            return (((0) <= (d_0_i_)) and ((d_0_i_) < (len(u)))) and ((default__.Ctl((u)[d_0_i_])) or (((u)[d_0_i_]) == (_dafny.CodePoint('\\'))))

        return _dafny.quantifier(_dafny.IntegerRange(0, len(u)), False, lambda0_)

    @staticmethod
    def SameSitePath(u):
        return ((((len(u)) >= (1)) and (((u)[0]) == (_dafny.CodePoint('/')))) and (((len(u)) == (1)) or ((((u)[1]) != (_dafny.CodePoint('/'))) and (((u)[1]) != (_dafny.CodePoint('\\')))))) and (not(default__.Bad(u)))

    @staticmethod
    def SafeRedirect(url, p, allowed, default):
        r: _dafny.Seq = _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, ""))
        if default__.Bad(url):
            r = default
            return r
        if (((p).scheme) == (_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")))) and (not((p).hasNetloc)):
            if (((len(url)) >= (1)) and (((url)[0]) == (_dafny.CodePoint('/')))) and (((len(url)) == (1)) or ((((url)[1]) != (_dafny.CodePoint('/'))) and (((url)[1]) != (_dafny.CodePoint('\\'))))):
                r = url
                return r
            r = default
            return r
        if ((((p).scheme) == (_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "http")))) or (((p).scheme) == (_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "https"))))) and (((p).host) in (allowed)):
            r = url
            return r
        r = default
        return r
        return r


class Parsed:
    @classmethod
    def default(cls, ):
        return lambda: Parsed_Parsed(_dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), _dafny.SeqWithoutIsStrInference(map(_dafny.CodePoint, "")), False)
    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)
    @property
    def is_Parsed(self) -> bool:
        return isinstance(self, Parsed_Parsed)

class Parsed_Parsed(Parsed, NamedTuple('Parsed', [('scheme', Any), ('host', Any), ('hasNetloc', Any)])):
    def __dafnystr__(self) -> str:
        return f'Redirect.Parsed.Parsed({self.scheme.VerbatimString(True)}, {self.host.VerbatimString(True)}, {_dafny.string_of(self.hasNetloc)})'
    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Parsed_Parsed) and self.scheme == __o.scheme and self.host == __o.host and self.hasNetloc == __o.hasNetloc
    def __hash__(self) -> int:
        return super().__hash__()

