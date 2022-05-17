#
# Copyright (c) 2022 Samuel J. McKelvie
#
# MIT License - See LICENSE file accompanying this package.
#

"""Type hints used internally by this package"""

from typing import (
    Dict,
    Union,
    Any,
    List,
    TYPE_CHECKING,
  )

if TYPE_CHECKING:
  Jsonable = Union[str, int, float, bool, None, Dict[str, Any], List[Any]]
  """A Type hint for a simple JSON-serializable value; i.e., str, int, float, bool, None, Dict[str, Jsonable], List[Jsonable]"""
else:
  Jsonable = Union[str, int, float, bool, None, Dict[str, 'Jsonable'], List['Jsonable']]
  """A Type hint for a simple JSON-serializable value; i.e., str, int, float, bool, None, Dict[str, Jsonable], List[Jsonable]"""

JsonableDict = Dict[str, Jsonable]
"""A type hint for a simple JSON-serializable dict; i.e., Dict[str, Jsonable]"""
