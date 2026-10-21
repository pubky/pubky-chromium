// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef THIRD_PARTY_BLINK_RENDERER_MODULES_PUBKY_PUBKY_SESSION_REQUESTER_H_
#define THIRD_PARTY_BLINK_RENDERER_MODULES_PUBKY_PUBKY_SESSION_REQUESTER_H_

#include "third_party/blink/public/mojom/pubky/pubky.mojom-blink.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/mojo/heap_mojo_remote.h"
#include "third_party/blink/renderer/platform/supplementable.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/vector.h"

namespace blink {

class ExceptionState;
class Navigator;
class PubkyCapabilities;
class PubkySession;
class ScriptPromiseResolverBase;
class ScriptState;

// navigator.pubky.requestSession(): asks the browser for a session with the
// user's Pubky identity. The browser keeps the credentials and enforces the
// scopes; this side only forwards calls. One per Navigator, holding the
// connection to the browser that the document's sessions share. See
// pubky/SESSIONS.md.
class PubkySessionRequester final
    : public GarbageCollected<PubkySessionRequester>,
      public Supplement<Navigator> {
 public:
  static const char kSupplementName[];

  static PubkySessionRequester& From(Navigator& navigator);

  // PubkyCapabilities.requestSession().
  static ScriptPromise<PubkySession> requestSession(
      ScriptState* script_state,
      PubkyCapabilities& capabilities,
      const Vector<String>& scopes,
      ExceptionState& exception_state);

  explicit PubkySessionRequester(Navigator& navigator);

  // The browser side for this document. Throws and returns null when the
  // document is no longer active.
  mojom::blink::PubkySessionHost* GetHost(ScriptState* script_state,
                                          ExceptionState& exception_state);

  // Rejects `resolver` with the exception for a failed call.
  static void Reject(ScriptPromiseResolverBase* resolver,
                     mojom::blink::PubkyStatus status);

  void Trace(Visitor* visitor) const override;

 private:
  ScriptPromise<PubkySession> RequestSession(ScriptState* script_state,
                                             const Vector<String>& scopes,
                                             ExceptionState& exception_state);
  void OnRequestSession(ScriptPromiseResolver<PubkySession>* resolver,
                        mojom::blink::PubkyStatus status,
                        const String& public_key);

  HeapMojoRemote<mojom::blink::PubkySessionHost> host_;
};

}  // namespace blink

#endif  // THIRD_PARTY_BLINK_RENDERER_MODULES_PUBKY_PUBKY_SESSION_REQUESTER_H_
