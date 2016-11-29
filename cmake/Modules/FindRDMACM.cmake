FIND_PATH(RDMACM_INCLUDE_DIR infiniband/verbs.h
  PATHS
  $ENV{RDMACM_HOME}
  NO_DEFAULT_PATH
    PATH_SUFFIXES include
)

FIND_PATH(RDMACM_INCLUDE_DIR rdma/rdma_cma.h
  PATHS
  /usr/local/include
  /usr/include
  /sw/include # Fink
  /opt/local/include # DarwinPorts
  /opt/csw/include # Blastwave
  /opt/include
)

FIND_LIBRARY(RDMACM_LIBRARY 
  NAMES rdmacm
  PATHS $ENV{RDMACM_HOME}
    NO_DEFAULT_PATH
    PATH_SUFFIXES lib64 lib
)

FIND_LIBRARY(RDMACM_LIBRARY 
  NAMES rdmacm
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

SET(RDMACM_FOUND "NO")
IF(RDMACM_LIBRARY AND RDMACM_INCLUDE_DIR)
  SET(RDMACM_FOUND "YES")
  ENDIF(RDMACM_LIBRARY AND RDMACM_INCLUDE_DIR)
