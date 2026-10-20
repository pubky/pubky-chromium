// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_PUBKY_PUBKY_SESSION_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_PUBKY_PUBKY_SESSION_H_

#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_typedefs.h"
#include "third_party/blink/renderer/platform/bindings/script_wrappable.h"
#include "third_party/blink/renderer/platform/heap/member.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"

namespace blink {

class ExceptionState;
class PubkySessionRequester;
class PubkyListOptions;
class Response;
class ScriptState;

// The handle navigator.pubky.requestSession() resolves to. Every call goes to
// the browser, which checks the path against the origin's allowed scopes at
// that moment, so a revoked site fails on its next call.
class PubkySession final : public ScriptWrappable {
  DEFINE_WRAPPERTYPEINFO();

 public:
  PubkySession(PubkySessionRequester* requester, const String& public_key);
  ~PubkySession() override;

  const String& publicKey() const { return public_key_; }

  ScriptPromise<Response> get(ScriptState* script_state,
                              const String& path,
                              ExceptionState& exception_state);
  ScriptPromise<IDLUndefined> put(ScriptState* script_state,
                                  const String& path,
                                  const V8BufferSource* body,
                                  const String& content_type,
                                  ExceptionState& exception_state);
  ScriptPromise<IDLUndefined> Delete(ScriptState* script_state,
                                     const String& path,
                                     ExceptionState& exception_state);
  ScriptPromise<IDLSequence<IDLUSVString>> list(
      ScriptState* script_state,
      const String& path,
      const PubkyListOptions* options,
      ExceptionState& exception_state);

  void Trace(Visitor* visitor) const override;

 private:
  Member<PubkySessionRequester> requester_;
  const String public_key_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_PUBKY_PUBKY_SESSION_H_
