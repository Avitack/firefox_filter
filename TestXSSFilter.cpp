/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=8 sts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "gtest/gtest.h"
#include "mozilla/dom/XSSFilter.h"

namespace mozilla {
namespace dom {

NS_NAMED_LITERAL_CSTRING(paramSafe, "some safe query123 __33z");
NS_NAMED_LITERAL_CSTRING(paramUnsafe, "query<script could be dangerous");
NS_NAMED_LITERAL_CSTRING(paramUnsafe2, "tes/t");
NS_NAMED_LITERAL_CSTRING(paramUnsafe3, "t(est");
NS_NAMED_LITERAL_CSTRING(paramInlineScriptAlert, "some content<script>alert(1)</script>");
NS_NAMED_LITERAL_CSTRING(paramExternalScriptXSSRocks, "some content<script src='http://xss.rocks/xss.js'></script>");
NS_NAMED_LITERAL_CSTRING(paramOnEventhandlerAlert, "some content<img src='notfound' onerror='alert(1)' />");

NS_NAMED_LITERAL_CSTRING(scriptAlert, "alert(1)");
NS_NAMED_LITERAL_CSTRING(scriptURIXSSRocks, "http://xss.rocks/xss.js");

XSSFilter* xssFilter;

TEST(TestXSSFilter, MarkParamAsSafe) {
    xssFilter = new XSSFilter();
    ASSERT_TRUE(xssFilter->isOnlyAlphaNumeric(paramSafe));
    delete xssFilter;
}

TEST(TestXSSFilter, MarkParamAsUnsafe) {
    xssFilter = new XSSFilter();
    ASSERT_FALSE(xssFilter->isOnlyAlphaNumeric(paramUnsafe));
    delete xssFilter;
}
TEST(TestXSSFilter, MarkParamAsUnsafe2) {
    xssFilter = new XSSFilter();
    ASSERT_FALSE(xssFilter->isOnlyAlphaNumeric(paramUnsafe2));
    delete xssFilter;
}
TEST(TestXSSFilter, MarkParamAsUnsafe3) {
    xssFilter = new XSSFilter();
    ASSERT_FALSE(xssFilter->isOnlyAlphaNumeric(paramUnsafe3));
    delete xssFilter;
}

TEST(TestXSSFilter, DetectsSimpleInlineScript) {
    xssFilter = new XSSFilter();
    ASSERT_TRUE(xssFilter->isInjected(paramInlineScriptAlert, scriptAlert));
    delete xssFilter;
}

TEST(TestXSSFilter, DetectsSimpleExternalScript) {
    xssFilter = new XSSFilter();
    ASSERT_TRUE(xssFilter->isInjectedExternal(paramExternalScriptXSSRocks, scriptURIXSSRocks));
    delete xssFilter;
}

TEST(TestXSSFilter, DetectsOnEventHandlerScript) {
    xssFilter = new XSSFilter();
    ASSERT_TRUE(xssFilter->isInjected(paramOnEventhandlerAlert, scriptAlert));
    delete xssFilter;
}

}; // namespace dom
}; // namespace mozilla