# firefox_filter
XSS filter integrated in Firefox

#
Contains the XSS filter itself, XSSFilter.cpp and XSSFilter.h.

The files ScriptLoader.cpp, nsDocument.cpp and EventListenerManager.cpp contains a few lines invoking the filter. (search: xss)

TestXSSFilter.cpp contains some Unit tests
