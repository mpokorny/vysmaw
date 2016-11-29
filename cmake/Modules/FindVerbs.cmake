FIND_PATH(VERBS_INCLUDE_DIR infiniband/verbs.h
  PATHS
  $ENV{VERBS_HOME}
  NO_DEFAULT_PATH
    PATH_SUFFIXES include
)

FIND_PATH(VERBS_INCLUDE_DIR infiniband/verbs.h
  PATHS
  /usr/local/include
  /usr/include
  /sw/include # Fink
  /opt/local/include # DarwinPorts
  /opt/csw/include # Blastwave
  /opt/include
)

FIND_LIBRARY(VERBS_LIBRARY 
  NAMES ibverbs
  PATHS $ENV{VERBS_HOME}
    NO_DEFAULT_PATH
    PATH_SUFFIXES lib64 lib
)

FIND_LIBRARY(VERBS_LIBRARY 
  NAMES ibverbs
  PATHS
    /usr/local
    /usr
    /sw
    /opt/local
    /opt/csw
    /opt
    /usr/freeware
    PATH_SUFFIXES lib64 lib
)

SET(VERBS_FOUND "NO")
IF(VERBS_LIBRARY AND VERBS_INCLUDE_DIR)
  SET(VERBS_FOUND "YES")
  ENDIF(VERBS_LIBRARY AND VERBS_INCLUDE_DIR)
