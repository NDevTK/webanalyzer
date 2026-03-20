/* idl-data.js — Auto-generated from Chromium IDL + C++ taint analysis.
   DO NOT EDIT MANUALLY. Run: npm run generate-sinks
   Generated: 2026-03-17T22:42:25.530Z

   Sources:
     - Chromium IDL: TrustedTypes annotations (html/script/script-url sinks)
     - Chromium C++ taint analysis: navigation classification for [URL] properties
     - Runtime: trustedTypes.getPropertyType() overrides when available */

// Sink map: "tag:prop" or "*:prop" (all elements) → sink type
// Types: "TrustedHTML" | "TrustedScript" | "TrustedScriptURL" | "navigation"
const SINK_MAP = {
  "*:innerHTML": "TrustedHTML",
  "*:outerHTML": "TrustedHTML",
  "script:textContent": "TrustedScript",
  "script:innerText": "TrustedScript",
  "script:src": "TrustedScriptURL",
  "script:text": "TrustedScript",
  "style:textContent": "TrustedScript",
  "style:innerText": "TrustedScript",
  "a:href": "navigation",
  "embed:src": "TrustedScriptURL",
  "frame:src": "navigation",
  "frame:longDesc": "navigation",
  "iframe:src": "navigation",
  "iframe:srcdoc": "TrustedHTML",
  "iframe:longDesc": "navigation",
  "object:data": "TrustedScriptURL",
  "object:codeBase": "TrustedScriptURL",
  "Attr:textContent": "TrustedScript",
  "CDATASection:textContent": "TrustedScript",
  "CharacterData:textContent": "TrustedScript",
  "Comment:textContent": "TrustedScript",
  "ProcessingInstruction:textContent": "TrustedScript",
  "Text:textContent": "TrustedScript",
  "XMLDocument:textContent": "TrustedScript",
  "HTMLDocument:textContent": "TrustedScript",
  "HTMLMediaElement:textContent": "TrustedScript",
  "HTMLMediaElement:innerHTML": "TrustedHTML",
  "HTMLMediaElement:outerHTML": "TrustedHTML",
  "HTMLMediaElement:innerText": "TrustedScript",
  "MathMLElement:textContent": "TrustedScript",
  "MathMLElement:innerHTML": "TrustedHTML",
  "MathMLElement:outerHTML": "TrustedHTML",
  "SVGAnimatedString:baseVal": "TrustedScriptURL",
  "SVGAnimateElement:textContent": "TrustedScript",
  "SVGAnimateElement:innerHTML": "TrustedHTML",
  "SVGAnimateElement:outerHTML": "TrustedHTML",
  "SVGAnimateMotionElement:textContent": "TrustedScript",
  "SVGAnimateMotionElement:innerHTML": "TrustedHTML",
  "SVGAnimateMotionElement:outerHTML": "TrustedHTML",
  "SVGAnimateTransformElement:textContent": "TrustedScript",
  "SVGAnimateTransformElement:innerHTML": "TrustedHTML",
  "SVGAnimateTransformElement:outerHTML": "TrustedHTML",
  "SVGAnimationElement:textContent": "TrustedScript",
  "SVGAnimationElement:innerHTML": "TrustedHTML",
  "SVGAnimationElement:outerHTML": "TrustedHTML",
  "SVGAElement:textContent": "TrustedScript",
  "SVGAElement:innerHTML": "TrustedHTML",
  "SVGAElement:outerHTML": "TrustedHTML",
  "SVGCircleElement:textContent": "TrustedScript",
  "SVGCircleElement:innerHTML": "TrustedHTML",
  "SVGCircleElement:outerHTML": "TrustedHTML",
  "SVGClipPathElement:textContent": "TrustedScript",
  "SVGClipPathElement:innerHTML": "TrustedHTML",
  "SVGClipPathElement:outerHTML": "TrustedHTML",
  "SVGComponentTransferFunctionElement:textContent": "TrustedScript",
  "SVGComponentTransferFunctionElement:innerHTML": "TrustedHTML",
  "SVGComponentTransferFunctionElement:outerHTML": "TrustedHTML",
  "SVGDefsElement:textContent": "TrustedScript",
  "SVGDefsElement:innerHTML": "TrustedHTML",
  "SVGDefsElement:outerHTML": "TrustedHTML",
  "SVGDescElement:textContent": "TrustedScript",
  "SVGDescElement:innerHTML": "TrustedHTML",
  "SVGDescElement:outerHTML": "TrustedHTML",
  "SVGEllipseElement:textContent": "TrustedScript",
  "SVGEllipseElement:innerHTML": "TrustedHTML",
  "SVGEllipseElement:outerHTML": "TrustedHTML",
  "SVGFEBlendElement:textContent": "TrustedScript",
  "SVGFEBlendElement:innerHTML": "TrustedHTML",
  "SVGFEBlendElement:outerHTML": "TrustedHTML",
  "SVGFEColorMatrixElement:textContent": "TrustedScript",
  "SVGFEColorMatrixElement:innerHTML": "TrustedHTML",
  "SVGFEColorMatrixElement:outerHTML": "TrustedHTML",
  "SVGFEComponentTransferElement:textContent": "TrustedScript",
  "SVGFEComponentTransferElement:innerHTML": "TrustedHTML",
  "SVGFEComponentTransferElement:outerHTML": "TrustedHTML",
  "SVGFECompositeElement:textContent": "TrustedScript",
  "SVGFECompositeElement:innerHTML": "TrustedHTML",
  "SVGFECompositeElement:outerHTML": "TrustedHTML",
  "SVGFEConvolveMatrixElement:textContent": "TrustedScript",
  "SVGFEConvolveMatrixElement:innerHTML": "TrustedHTML",
  "SVGFEConvolveMatrixElement:outerHTML": "TrustedHTML",
  "SVGFEDiffuseLightingElement:textContent": "TrustedScript",
  "SVGFEDiffuseLightingElement:innerHTML": "TrustedHTML",
  "SVGFEDiffuseLightingElement:outerHTML": "TrustedHTML",
  "SVGFEDisplacementMapElement:textContent": "TrustedScript",
  "SVGFEDisplacementMapElement:innerHTML": "TrustedHTML",
  "SVGFEDisplacementMapElement:outerHTML": "TrustedHTML",
  "SVGFEDistantLightElement:textContent": "TrustedScript",
  "SVGFEDistantLightElement:innerHTML": "TrustedHTML",
  "SVGFEDistantLightElement:outerHTML": "TrustedHTML",
  "SVGFEDropShadowElement:textContent": "TrustedScript",
  "SVGFEDropShadowElement:innerHTML": "TrustedHTML",
  "SVGFEDropShadowElement:outerHTML": "TrustedHTML",
  "SVGFEFloodElement:textContent": "TrustedScript",
  "SVGFEFloodElement:innerHTML": "TrustedHTML",
  "SVGFEFloodElement:outerHTML": "TrustedHTML",
  "SVGFEFuncAElement:textContent": "TrustedScript",
  "SVGFEFuncAElement:innerHTML": "TrustedHTML",
  "SVGFEFuncAElement:outerHTML": "TrustedHTML",
  "SVGFEFuncBElement:textContent": "TrustedScript",
  "SVGFEFuncBElement:innerHTML": "TrustedHTML",
  "SVGFEFuncBElement:outerHTML": "TrustedHTML",
  "SVGFEFuncGElement:textContent": "TrustedScript",
  "SVGFEFuncGElement:innerHTML": "TrustedHTML",
  "SVGFEFuncGElement:outerHTML": "TrustedHTML",
  "SVGFEFuncRElement:textContent": "TrustedScript",
  "SVGFEFuncRElement:innerHTML": "TrustedHTML",
  "SVGFEFuncRElement:outerHTML": "TrustedHTML",
  "SVGFEGaussianBlurElement:textContent": "TrustedScript",
  "SVGFEGaussianBlurElement:innerHTML": "TrustedHTML",
  "SVGFEGaussianBlurElement:outerHTML": "TrustedHTML",
  "SVGFEImageElement:textContent": "TrustedScript",
  "SVGFEImageElement:innerHTML": "TrustedHTML",
  "SVGFEImageElement:outerHTML": "TrustedHTML",
  "SVGFEMergeElement:textContent": "TrustedScript",
  "SVGFEMergeElement:innerHTML": "TrustedHTML",
  "SVGFEMergeElement:outerHTML": "TrustedHTML",
  "SVGFEMergeNodeElement:textContent": "TrustedScript",
  "SVGFEMergeNodeElement:innerHTML": "TrustedHTML",
  "SVGFEMergeNodeElement:outerHTML": "TrustedHTML",
  "SVGFEMorphologyElement:textContent": "TrustedScript",
  "SVGFEMorphologyElement:innerHTML": "TrustedHTML",
  "SVGFEMorphologyElement:outerHTML": "TrustedHTML",
  "SVGFEOffsetElement:textContent": "TrustedScript",
  "SVGFEOffsetElement:innerHTML": "TrustedHTML",
  "SVGFEOffsetElement:outerHTML": "TrustedHTML",
  "SVGFEPointLightElement:textContent": "TrustedScript",
  "SVGFEPointLightElement:innerHTML": "TrustedHTML",
  "SVGFEPointLightElement:outerHTML": "TrustedHTML",
  "SVGFESpecularLightingElement:textContent": "TrustedScript",
  "SVGFESpecularLightingElement:innerHTML": "TrustedHTML",
  "SVGFESpecularLightingElement:outerHTML": "TrustedHTML",
  "SVGFESpotLightElement:textContent": "TrustedScript",
  "SVGFESpotLightElement:innerHTML": "TrustedHTML",
  "SVGFESpotLightElement:outerHTML": "TrustedHTML",
  "SVGFETileElement:textContent": "TrustedScript",
  "SVGFETileElement:innerHTML": "TrustedHTML",
  "SVGFETileElement:outerHTML": "TrustedHTML",
  "SVGFETurbulenceElement:textContent": "TrustedScript",
  "SVGFETurbulenceElement:innerHTML": "TrustedHTML",
  "SVGFETurbulenceElement:outerHTML": "TrustedHTML",
  "SVGFilterElement:textContent": "TrustedScript",
  "SVGFilterElement:innerHTML": "TrustedHTML",
  "SVGFilterElement:outerHTML": "TrustedHTML",
  "SVGForeignObjectElement:textContent": "TrustedScript",
  "SVGForeignObjectElement:innerHTML": "TrustedHTML",
  "SVGForeignObjectElement:outerHTML": "TrustedHTML",
  "SVGGeometryElement:textContent": "TrustedScript",
  "SVGGeometryElement:innerHTML": "TrustedHTML",
  "SVGGeometryElement:outerHTML": "TrustedHTML",
  "SVGGradientElement:textContent": "TrustedScript",
  "SVGGradientElement:innerHTML": "TrustedHTML",
  "SVGGradientElement:outerHTML": "TrustedHTML",
  "SVGGraphicsElement:textContent": "TrustedScript",
  "SVGGraphicsElement:innerHTML": "TrustedHTML",
  "SVGGraphicsElement:outerHTML": "TrustedHTML",
  "SVGGElement:textContent": "TrustedScript",
  "SVGGElement:innerHTML": "TrustedHTML",
  "SVGGElement:outerHTML": "TrustedHTML",
  "SVGImageElement:textContent": "TrustedScript",
  "SVGImageElement:innerHTML": "TrustedHTML",
  "SVGImageElement:outerHTML": "TrustedHTML",
  "SVGLinearGradientElement:textContent": "TrustedScript",
  "SVGLinearGradientElement:innerHTML": "TrustedHTML",
  "SVGLinearGradientElement:outerHTML": "TrustedHTML",
  "SVGLineElement:textContent": "TrustedScript",
  "SVGLineElement:innerHTML": "TrustedHTML",
  "SVGLineElement:outerHTML": "TrustedHTML",
  "SVGMarkerElement:textContent": "TrustedScript",
  "SVGMarkerElement:innerHTML": "TrustedHTML",
  "SVGMarkerElement:outerHTML": "TrustedHTML",
  "SVGMaskElement:textContent": "TrustedScript",
  "SVGMaskElement:innerHTML": "TrustedHTML",
  "SVGMaskElement:outerHTML": "TrustedHTML",
  "SVGMetadataElement:textContent": "TrustedScript",
  "SVGMetadataElement:innerHTML": "TrustedHTML",
  "SVGMetadataElement:outerHTML": "TrustedHTML",
  "SVGMPathElement:textContent": "TrustedScript",
  "SVGMPathElement:innerHTML": "TrustedHTML",
  "SVGMPathElement:outerHTML": "TrustedHTML",
  "SVGPathElement:textContent": "TrustedScript",
  "SVGPathElement:innerHTML": "TrustedHTML",
  "SVGPathElement:outerHTML": "TrustedHTML",
  "SVGPatternElement:textContent": "TrustedScript",
  "SVGPatternElement:innerHTML": "TrustedHTML",
  "SVGPatternElement:outerHTML": "TrustedHTML",
  "SVGPolygonElement:textContent": "TrustedScript",
  "SVGPolygonElement:innerHTML": "TrustedHTML",
  "SVGPolygonElement:outerHTML": "TrustedHTML",
  "SVGPolylineElement:textContent": "TrustedScript",
  "SVGPolylineElement:innerHTML": "TrustedHTML",
  "SVGPolylineElement:outerHTML": "TrustedHTML",
  "SVGRadialGradientElement:textContent": "TrustedScript",
  "SVGRadialGradientElement:innerHTML": "TrustedHTML",
  "SVGRadialGradientElement:outerHTML": "TrustedHTML",
  "SVGRectElement:textContent": "TrustedScript",
  "SVGRectElement:innerHTML": "TrustedHTML",
  "SVGRectElement:outerHTML": "TrustedHTML",
  "SVGScriptElement:textContent": "TrustedScript",
  "SVGScriptElement:innerHTML": "TrustedHTML",
  "SVGScriptElement:outerHTML": "TrustedHTML",
  "SVGSetElement:textContent": "TrustedScript",
  "SVGSetElement:innerHTML": "TrustedHTML",
  "SVGSetElement:outerHTML": "TrustedHTML",
  "SVGStopElement:textContent": "TrustedScript",
  "SVGStopElement:innerHTML": "TrustedHTML",
  "SVGStopElement:outerHTML": "TrustedHTML",
  "SVGStyleElement:textContent": "TrustedScript",
  "SVGStyleElement:innerHTML": "TrustedHTML",
  "SVGStyleElement:outerHTML": "TrustedHTML",
  "SVGSVGElement:textContent": "TrustedScript",
  "SVGSVGElement:innerHTML": "TrustedHTML",
  "SVGSVGElement:outerHTML": "TrustedHTML",
  "SVGSwitchElement:textContent": "TrustedScript",
  "SVGSwitchElement:innerHTML": "TrustedHTML",
  "SVGSwitchElement:outerHTML": "TrustedHTML",
  "SVGSymbolElement:textContent": "TrustedScript",
  "SVGSymbolElement:innerHTML": "TrustedHTML",
  "SVGSymbolElement:outerHTML": "TrustedHTML",
  "SVGTextContentElement:textContent": "TrustedScript",
  "SVGTextContentElement:innerHTML": "TrustedHTML",
  "SVGTextContentElement:outerHTML": "TrustedHTML",
  "SVGTextElement:textContent": "TrustedScript",
  "SVGTextElement:innerHTML": "TrustedHTML",
  "SVGTextElement:outerHTML": "TrustedHTML",
  "SVGTextPathElement:textContent": "TrustedScript",
  "SVGTextPathElement:innerHTML": "TrustedHTML",
  "SVGTextPathElement:outerHTML": "TrustedHTML",
  "SVGTextPositioningElement:textContent": "TrustedScript",
  "SVGTextPositioningElement:innerHTML": "TrustedHTML",
  "SVGTextPositioningElement:outerHTML": "TrustedHTML",
  "SVGTitleElement:textContent": "TrustedScript",
  "SVGTitleElement:innerHTML": "TrustedHTML",
  "SVGTitleElement:outerHTML": "TrustedHTML",
  "SVGTSpanElement:textContent": "TrustedScript",
  "SVGTSpanElement:innerHTML": "TrustedHTML",
  "SVGTSpanElement:outerHTML": "TrustedHTML",
  "SVGUseElement:textContent": "TrustedScript",
  "SVGUseElement:innerHTML": "TrustedHTML",
  "SVGUseElement:outerHTML": "TrustedHTML",
  "SVGViewElement:textContent": "TrustedScript",
  "SVGViewElement:innerHTML": "TrustedHTML",
  "SVGViewElement:outerHTML": "TrustedHTML",
  "TrustedHTML:fromLiteral": "TrustedHTML",
  "TrustedScript:fromLiteral": "TrustedScript",
  "TrustedScriptURL:fromLiteral": "TrustedScriptURL",
  "TrustedTypePolicy:createHTML": "TrustedHTML",
  "TrustedTypePolicy:createScript": "TrustedScript",
  "TrustedTypePolicy:createScriptURL": "TrustedScriptURL",
  "Document:textContent": "TrustedScript",
  "DocumentFragment:textContent": "TrustedScript",
  "DocumentType:textContent": "TrustedScript",
  "ShadowRoot:textContent": "TrustedScript",
  "ShadowRoot:innerHTML": "TrustedHTML"
};

// Runtime sink cache — merges static data with trustedTypes.getPropertyType()
let _sinkCache = null;

function _buildSinkMap() {
  const sinks = new Map();

  // Load static sink data
  for (const [key, type] of Object.entries(SINK_MAP)) {
    sinks.set(key, { type, behavior: type === 'navigation' ? 'navigation' : 'injection' });
  }

  // Override with runtime trustedTypes.getPropertyType() if available
  const hasTT = typeof trustedTypes !== 'undefined' && typeof trustedTypes.getPropertyType === 'function';
  if (hasTT) {
    // Probe known element tags for additional sinks not in IDL data
    const tags = new Set();
    for (const key of Object.keys(SINK_MAP)) {
      const tag = key.split(':')[0];
      if (tag !== '*') tags.add(tag);
    }
    // The runtime probe can discover sinks our IDL parsing missed
    // but we trust our static data as the primary source
  }

  return sinks;
}

// Check if a property is a sink on a given element tag.
// Returns { type, behavior } or null.
// type: "TrustedHTML" | "TrustedScript" | "TrustedScriptURL" | "navigation"
export function isElementPropertySink(tag, propName) {
  if (!_sinkCache) _sinkCache = _buildSinkMap();
  // Check tag-specific first, then wildcard
  return _sinkCache.get(tag + ':' + propName) || _sinkCache.get('*:' + propName) || null;
}

// Check if a property exists as a sink on any element.
export function hasElementProperty(tag, propName) {
  if (!_sinkCache) _sinkCache = _buildSinkMap();
  return _sinkCache.has(tag + ':' + propName) || _sinkCache.has('*:' + propName);
}

// DOM-producing properties: properties that return Element subtypes (from IDL return types)
// "Interface.prop" → tag (string) or null (generic Element)
const DOM_PROPERTIES = {
  "Document.ownerDocument": null,
  "Document.parentNode": null,
  "Document.parentElement": null,
  "Document.childNodes": null,
  "Document.firstChild": null,
  "Document.lastChild": null,
  "Document.previousSibling": null,
  "Document.nextSibling": null,
  "Document.doctype": null,
  "Document.documentElement": null,
  "Document.body": null,
  "Document.head": "head",
  "Document.scrollingElement": null,
  "Document.webkitCurrentFullScreenElement": null,
  "Document.webkitFullscreenElement": null,
  "Document.rootElement": null,
  "Document.firstElementChild": null,
  "Document.lastElementChild": null,
  "Document.activeElement": null,
  "Document.pointerLockElement": null,
  "Document.fullscreenElement": null,
  "Document.pictureInPictureElement": null,
  "Document.customElementRegistry": null,
  "KeyframeEffect.target": null,
  "ScrollTimeline.source": null,
  "ViewTimeline.source": null,
  "ViewTimeline.subject": null,
  "CaretPosition.offsetNode": null,
  "Element.ownerDocument": null,
  "Element.parentNode": null,
  "Element.parentElement": null,
  "Element.childNodes": null,
  "Element.firstChild": null,
  "Element.lastChild": null,
  "Element.previousSibling": null,
  "Element.nextSibling": null,
  "Element.attributes": null,
  "Element.shadowRoot": null,
  "Element.assignedSlot": "slot",
  "Element.customElementRegistry": null,
  "Element.ariaActiveDescendantElement": null,
  "Element.ariaControlsElements": null,
  "Element.ariaDescribedByElements": null,
  "Element.ariaDetailsElements": null,
  "Element.ariaErrorMessageElements": null,
  "Element.ariaFlowToElements": null,
  "Element.ariaLabelledByElements": null,
  "Element.ariaOwnsElements": null,
  "Element.firstElementChild": null,
  "Element.lastElementChild": null,
  "Element.previousElementSibling": null,
  "Element.nextElementSibling": null,
  "CSSStyleSheet.ownerNode": null,
  "StyleSheet.ownerNode": null,
  "AbstractRange.startContainer": null,
  "AbstractRange.endContainer": null,
  "Attr.ownerDocument": null,
  "Attr.parentNode": null,
  "Attr.parentElement": null,
  "Attr.childNodes": null,
  "Attr.firstChild": null,
  "Attr.lastChild": null,
  "Attr.previousSibling": null,
  "Attr.nextSibling": null,
  "Attr.ownerElement": null,
  "CDATASection.ownerDocument": null,
  "CDATASection.parentNode": null,
  "CDATASection.parentElement": null,
  "CDATASection.childNodes": null,
  "CDATASection.firstChild": null,
  "CDATASection.lastChild": null,
  "CDATASection.previousSibling": null,
  "CDATASection.nextSibling": null,
  "CDATASection.previousElementSibling": null,
  "CDATASection.nextElementSibling": null,
  "CDATASection.assignedSlot": "slot",
  "CharacterData.ownerDocument": null,
  "CharacterData.parentNode": null,
  "CharacterData.parentElement": null,
  "CharacterData.childNodes": null,
  "CharacterData.firstChild": null,
  "CharacterData.lastChild": null,
  "CharacterData.previousSibling": null,
  "CharacterData.nextSibling": null,
  "CharacterData.previousElementSibling": null,
  "CharacterData.nextElementSibling": null,
  "Comment.ownerDocument": null,
  "Comment.parentNode": null,
  "Comment.parentElement": null,
  "Comment.childNodes": null,
  "Comment.firstChild": null,
  "Comment.lastChild": null,
  "Comment.previousSibling": null,
  "Comment.nextSibling": null,
  "Comment.previousElementSibling": null,
  "Comment.nextElementSibling": null,
  "CSSPseudoElement.element": null,
  "CSSPseudoElement.parent": null,
  "DocumentFragment.ownerDocument": null,
  "DocumentFragment.parentNode": null,
  "DocumentFragment.parentElement": null,
  "DocumentFragment.childNodes": null,
  "DocumentFragment.firstChild": null,
  "DocumentFragment.lastChild": null,
  "DocumentFragment.previousSibling": null,
  "DocumentFragment.nextSibling": null,
  "DocumentFragment.firstElementChild": null,
  "DocumentFragment.lastElementChild": null,
  "DocumentType.ownerDocument": null,
  "DocumentType.parentNode": null,
  "DocumentType.parentElement": null,
  "DocumentType.childNodes": null,
  "DocumentType.firstChild": null,
  "DocumentType.lastChild": null,
  "DocumentType.previousSibling": null,
  "DocumentType.nextSibling": null,
  "MutationRecord.target": null,
  "MutationRecord.addedNodes": null,
  "MutationRecord.removedNodes": null,
  "MutationRecord.previousSibling": null,
  "MutationRecord.nextSibling": null,
  "Node.ownerDocument": null,
  "Node.parentNode": null,
  "Node.parentElement": null,
  "Node.childNodes": null,
  "Node.firstChild": null,
  "Node.lastChild": null,
  "Node.previousSibling": null,
  "Node.nextSibling": null,
  "NodeIterator.root": null,
  "NodeIterator.referenceNode": null,
  "NodeIterator.filter": null,
  "OpaqueRange.startContainer": null,
  "OpaqueRange.endContainer": null,
  "ProcessingInstruction.ownerDocument": null,
  "ProcessingInstruction.parentNode": null,
  "ProcessingInstruction.parentElement": null,
  "ProcessingInstruction.childNodes": null,
  "ProcessingInstruction.firstChild": null,
  "ProcessingInstruction.lastChild": null,
  "ProcessingInstruction.previousSibling": null,
  "ProcessingInstruction.nextSibling": null,
  "ProcessingInstruction.previousElementSibling": null,
  "ProcessingInstruction.nextElementSibling": null,
  "Range.startContainer": null,
  "Range.endContainer": null,
  "Range.commonAncestorContainer": null,
  "ShadowRoot.ownerDocument": null,
  "ShadowRoot.parentNode": null,
  "ShadowRoot.parentElement": null,
  "ShadowRoot.childNodes": null,
  "ShadowRoot.firstChild": null,
  "ShadowRoot.lastChild": null,
  "ShadowRoot.previousSibling": null,
  "ShadowRoot.nextSibling": null,
  "ShadowRoot.firstElementChild": null,
  "ShadowRoot.lastElementChild": null,
  "ShadowRoot.mode": null,
  "ShadowRoot.host": null,
  "ShadowRoot.activeElement": null,
  "ShadowRoot.pointerLockElement": null,
  "ShadowRoot.fullscreenElement": null,
  "ShadowRoot.pictureInPictureElement": null,
  "ShadowRoot.customElementRegistry": null,
  "StaticRange.startContainer": null,
  "StaticRange.endContainer": null,
  "Internals.visibleSelectionAnchorNode": null,
  "Internals.visibleSelectionFocusNode": null,
  "Text.ownerDocument": null,
  "Text.parentNode": null,
  "Text.parentElement": null,
  "Text.childNodes": null,
  "Text.firstChild": null,
  "Text.lastChild": null,
  "Text.previousSibling": null,
  "Text.nextSibling": null,
  "Text.previousElementSibling": null,
  "Text.nextElementSibling": null,
  "Text.assignedSlot": "slot",
  "TreeWalker.root": null,
  "TreeWalker.filter": null,
  "TreeWalker.currentNode": null,
  "XMLDocument.ownerDocument": null,
  "XMLDocument.parentNode": null,
  "XMLDocument.parentElement": null,
  "XMLDocument.childNodes": null,
  "XMLDocument.firstChild": null,
  "XMLDocument.lastChild": null,
  "XMLDocument.previousSibling": null,
  "XMLDocument.nextSibling": null,
  "XMLDocument.doctype": null,
  "XMLDocument.documentElement": null,
  "XMLDocument.body": null,
  "XMLDocument.head": "head",
  "XMLDocument.scrollingElement": null,
  "XMLDocument.webkitCurrentFullScreenElement": null,
  "XMLDocument.webkitFullscreenElement": null,
  "XMLDocument.rootElement": null,
  "XMLDocument.firstElementChild": null,
  "XMLDocument.lastElementChild": null,
  "XMLDocument.activeElement": null,
  "XMLDocument.pointerLockElement": null,
  "XMLDocument.fullscreenElement": null,
  "XMLDocument.pictureInPictureElement": null,
  "XMLDocument.customElementRegistry": null,
  "Selection.anchorNode": null,
  "Selection.focusNode": null,
  "Selection.baseNode": null,
  "Selection.extentNode": null,
  "AnimationEvent.pseudoTarget": null,
  "CommandEvent.source": null,
  "CompositionEvent.pseudoTarget": null,
  "DragEvent.pseudoTarget": null,
  "DragEvent.fromElement": null,
  "DragEvent.toElement": null,
  "FocusEvent.pseudoTarget": null,
  "InputEvent.pseudoTarget": null,
  "InterestEvent.source": null,
  "KeyboardEvent.pseudoTarget": null,
  "MouseEvent.pseudoTarget": null,
  "MouseEvent.fromElement": null,
  "MouseEvent.toElement": null,
  "PointerEvent.pseudoTarget": null,
  "PointerEvent.fromElement": null,
  "PointerEvent.toElement": null,
  "TextEvent.pseudoTarget": null,
  "ToggleEvent.source": null,
  "TouchEvent.pseudoTarget": null,
  "TransitionEvent.pseudoTarget": null,
  "UIEvent.pseudoTarget": null,
  "WheelEvent.pseudoTarget": null,
  "WheelEvent.fromElement": null,
  "WheelEvent.toElement": null,
  "Window.document": null,
  "Window.customElements": null,
  "Window.frameElement": null,
  "HighlightPointerEvent.pseudoTarget": null,
  "HighlightPointerEvent.fromElement": null,
  "HighlightPointerEvent.toElement": null,
  "CanvasPaintEvent.changedElements": null,
  "HTMLCanvasElement.ownerDocument": null,
  "HTMLCanvasElement.parentNode": null,
  "HTMLCanvasElement.parentElement": null,
  "HTMLCanvasElement.childNodes": null,
  "HTMLCanvasElement.firstChild": null,
  "HTMLCanvasElement.lastChild": null,
  "HTMLCanvasElement.previousSibling": null,
  "HTMLCanvasElement.nextSibling": null,
  "HTMLCanvasElement.attributes": null,
  "HTMLCanvasElement.shadowRoot": null,
  "HTMLCanvasElement.assignedSlot": "slot",
  "HTMLCanvasElement.customElementRegistry": null,
  "HTMLCanvasElement.ariaActiveDescendantElement": null,
  "HTMLCanvasElement.ariaControlsElements": null,
  "HTMLCanvasElement.ariaDescribedByElements": null,
  "HTMLCanvasElement.ariaDetailsElements": null,
  "HTMLCanvasElement.ariaErrorMessageElements": null,
  "HTMLCanvasElement.ariaFlowToElements": null,
  "HTMLCanvasElement.ariaLabelledByElements": null,
  "HTMLCanvasElement.ariaOwnsElements": null,
  "HTMLCanvasElement.firstElementChild": null,
  "HTMLCanvasElement.lastElementChild": null,
  "HTMLCanvasElement.previousElementSibling": null,
  "HTMLCanvasElement.nextElementSibling": null,
  "HTMLCanvasElement.scrollParent": null,
  "HTMLCanvasElement.offsetParent": null,
  "ElementInternals.form": null,
  "ElementInternals.labels": null,
  "ElementInternals.shadowRoot": null,
  "ElementInternals.ariaActiveDescendantElement": null,
  "ElementInternals.ariaControlsElements": null,
  "ElementInternals.ariaDescribedByElements": null,
  "ElementInternals.ariaDetailsElements": null,
  "ElementInternals.ariaErrorMessageElements": null,
  "ElementInternals.ariaFlowToElements": null,
  "ElementInternals.ariaLabelledByElements": null,
  "ElementInternals.ariaOwnsElements": null,
  "HTMLFencedFrameElement.ownerDocument": null,
  "HTMLFencedFrameElement.parentNode": null,
  "HTMLFencedFrameElement.parentElement": null,
  "HTMLFencedFrameElement.childNodes": null,
  "HTMLFencedFrameElement.firstChild": null,
  "HTMLFencedFrameElement.lastChild": null,
  "HTMLFencedFrameElement.previousSibling": null,
  "HTMLFencedFrameElement.nextSibling": null,
  "HTMLFencedFrameElement.attributes": null,
  "HTMLFencedFrameElement.shadowRoot": null,
  "HTMLFencedFrameElement.assignedSlot": "slot",
  "HTMLFencedFrameElement.customElementRegistry": null,
  "HTMLFencedFrameElement.ariaActiveDescendantElement": null,
  "HTMLFencedFrameElement.ariaControlsElements": null,
  "HTMLFencedFrameElement.ariaDescribedByElements": null,
  "HTMLFencedFrameElement.ariaDetailsElements": null,
  "HTMLFencedFrameElement.ariaErrorMessageElements": null,
  "HTMLFencedFrameElement.ariaFlowToElements": null,
  "HTMLFencedFrameElement.ariaLabelledByElements": null,
  "HTMLFencedFrameElement.ariaOwnsElements": null,
  "HTMLFencedFrameElement.firstElementChild": null,
  "HTMLFencedFrameElement.lastElementChild": null,
  "HTMLFencedFrameElement.previousElementSibling": null,
  "HTMLFencedFrameElement.nextElementSibling": null,
  "HTMLFencedFrameElement.scrollParent": null,
  "HTMLFencedFrameElement.offsetParent": null,
  "HTMLButtonElement.ownerDocument": null,
  "HTMLButtonElement.parentNode": null,
  "HTMLButtonElement.parentElement": null,
  "HTMLButtonElement.childNodes": null,
  "HTMLButtonElement.firstChild": null,
  "HTMLButtonElement.lastChild": null,
  "HTMLButtonElement.previousSibling": null,
  "HTMLButtonElement.nextSibling": null,
  "HTMLButtonElement.attributes": null,
  "HTMLButtonElement.shadowRoot": null,
  "HTMLButtonElement.assignedSlot": "slot",
  "HTMLButtonElement.customElementRegistry": null,
  "HTMLButtonElement.ariaActiveDescendantElement": null,
  "HTMLButtonElement.ariaControlsElements": null,
  "HTMLButtonElement.ariaDescribedByElements": null,
  "HTMLButtonElement.ariaDetailsElements": null,
  "HTMLButtonElement.ariaErrorMessageElements": null,
  "HTMLButtonElement.ariaFlowToElements": null,
  "HTMLButtonElement.ariaLabelledByElements": null,
  "HTMLButtonElement.ariaOwnsElements": null,
  "HTMLButtonElement.firstElementChild": null,
  "HTMLButtonElement.lastElementChild": null,
  "HTMLButtonElement.previousElementSibling": null,
  "HTMLButtonElement.nextElementSibling": null,
  "HTMLButtonElement.scrollParent": null,
  "HTMLButtonElement.offsetParent": null,
  "HTMLButtonElement.form": null,
  "HTMLButtonElement.labels": null,
  "HTMLButtonElement.popoverTargetElement": null,
  "HTMLButtonElement.commandForElement": null,
  "HTMLButtonElement.interestForElement": null,
  "HTMLDataListElement.ownerDocument": null,
  "HTMLDataListElement.parentNode": null,
  "HTMLDataListElement.parentElement": null,
  "HTMLDataListElement.childNodes": null,
  "HTMLDataListElement.firstChild": null,
  "HTMLDataListElement.lastChild": null,
  "HTMLDataListElement.previousSibling": null,
  "HTMLDataListElement.nextSibling": null,
  "HTMLDataListElement.attributes": null,
  "HTMLDataListElement.shadowRoot": null,
  "HTMLDataListElement.assignedSlot": "slot",
  "HTMLDataListElement.customElementRegistry": null,
  "HTMLDataListElement.ariaActiveDescendantElement": null,
  "HTMLDataListElement.ariaControlsElements": null,
  "HTMLDataListElement.ariaDescribedByElements": null,
  "HTMLDataListElement.ariaDetailsElements": null,
  "HTMLDataListElement.ariaErrorMessageElements": null,
  "HTMLDataListElement.ariaFlowToElements": null,
  "HTMLDataListElement.ariaLabelledByElements": null,
  "HTMLDataListElement.ariaOwnsElements": null,
  "HTMLDataListElement.firstElementChild": null,
  "HTMLDataListElement.lastElementChild": null,
  "HTMLDataListElement.previousElementSibling": null,
  "HTMLDataListElement.nextElementSibling": null,
  "HTMLDataListElement.scrollParent": null,
  "HTMLDataListElement.offsetParent": null,
  "HTMLFieldSetElement.ownerDocument": null,
  "HTMLFieldSetElement.parentNode": null,
  "HTMLFieldSetElement.parentElement": null,
  "HTMLFieldSetElement.childNodes": null,
  "HTMLFieldSetElement.firstChild": null,
  "HTMLFieldSetElement.lastChild": null,
  "HTMLFieldSetElement.previousSibling": null,
  "HTMLFieldSetElement.nextSibling": null,
  "HTMLFieldSetElement.attributes": null,
  "HTMLFieldSetElement.shadowRoot": null,
  "HTMLFieldSetElement.assignedSlot": "slot",
  "HTMLFieldSetElement.customElementRegistry": null,
  "HTMLFieldSetElement.ariaActiveDescendantElement": null,
  "HTMLFieldSetElement.ariaControlsElements": null,
  "HTMLFieldSetElement.ariaDescribedByElements": null,
  "HTMLFieldSetElement.ariaDetailsElements": null,
  "HTMLFieldSetElement.ariaErrorMessageElements": null,
  "HTMLFieldSetElement.ariaFlowToElements": null,
  "HTMLFieldSetElement.ariaLabelledByElements": null,
  "HTMLFieldSetElement.ariaOwnsElements": null,
  "HTMLFieldSetElement.firstElementChild": null,
  "HTMLFieldSetElement.lastElementChild": null,
  "HTMLFieldSetElement.previousElementSibling": null,
  "HTMLFieldSetElement.nextElementSibling": null,
  "HTMLFieldSetElement.scrollParent": null,
  "HTMLFieldSetElement.offsetParent": null,
  "HTMLFieldSetElement.form": null,
  "HTMLFormElement.ownerDocument": null,
  "HTMLFormElement.parentNode": null,
  "HTMLFormElement.parentElement": null,
  "HTMLFormElement.childNodes": null,
  "HTMLFormElement.firstChild": null,
  "HTMLFormElement.lastChild": null,
  "HTMLFormElement.previousSibling": null,
  "HTMLFormElement.nextSibling": null,
  "HTMLFormElement.attributes": null,
  "HTMLFormElement.shadowRoot": null,
  "HTMLFormElement.assignedSlot": "slot",
  "HTMLFormElement.customElementRegistry": null,
  "HTMLFormElement.ariaActiveDescendantElement": null,
  "HTMLFormElement.ariaControlsElements": null,
  "HTMLFormElement.ariaDescribedByElements": null,
  "HTMLFormElement.ariaDetailsElements": null,
  "HTMLFormElement.ariaErrorMessageElements": null,
  "HTMLFormElement.ariaFlowToElements": null,
  "HTMLFormElement.ariaLabelledByElements": null,
  "HTMLFormElement.ariaOwnsElements": null,
  "HTMLFormElement.firstElementChild": null,
  "HTMLFormElement.lastElementChild": null,
  "HTMLFormElement.previousElementSibling": null,
  "HTMLFormElement.nextElementSibling": null,
  "HTMLFormElement.scrollParent": null,
  "HTMLFormElement.offsetParent": null,
  "HTMLInputElement.ownerDocument": null,
  "HTMLInputElement.parentNode": null,
  "HTMLInputElement.parentElement": null,
  "HTMLInputElement.childNodes": null,
  "HTMLInputElement.firstChild": null,
  "HTMLInputElement.lastChild": null,
  "HTMLInputElement.previousSibling": null,
  "HTMLInputElement.nextSibling": null,
  "HTMLInputElement.attributes": null,
  "HTMLInputElement.shadowRoot": null,
  "HTMLInputElement.assignedSlot": "slot",
  "HTMLInputElement.customElementRegistry": null,
  "HTMLInputElement.ariaActiveDescendantElement": null,
  "HTMLInputElement.ariaControlsElements": null,
  "HTMLInputElement.ariaDescribedByElements": null,
  "HTMLInputElement.ariaDetailsElements": null,
  "HTMLInputElement.ariaErrorMessageElements": null,
  "HTMLInputElement.ariaFlowToElements": null,
  "HTMLInputElement.ariaLabelledByElements": null,
  "HTMLInputElement.ariaOwnsElements": null,
  "HTMLInputElement.firstElementChild": null,
  "HTMLInputElement.lastElementChild": null,
  "HTMLInputElement.previousElementSibling": null,
  "HTMLInputElement.nextElementSibling": null,
  "HTMLInputElement.scrollParent": null,
  "HTMLInputElement.offsetParent": null,
  "HTMLInputElement.form": null,
  "HTMLInputElement.list": null,
  "HTMLInputElement.labels": null,
  "HTMLInputElement.popoverTargetElement": null,
  "HTMLLabelElement.ownerDocument": null,
  "HTMLLabelElement.parentNode": null,
  "HTMLLabelElement.parentElement": null,
  "HTMLLabelElement.childNodes": null,
  "HTMLLabelElement.firstChild": null,
  "HTMLLabelElement.lastChild": null,
  "HTMLLabelElement.previousSibling": null,
  "HTMLLabelElement.nextSibling": null,
  "HTMLLabelElement.attributes": null,
  "HTMLLabelElement.shadowRoot": null,
  "HTMLLabelElement.assignedSlot": "slot",
  "HTMLLabelElement.customElementRegistry": null,
  "HTMLLabelElement.ariaActiveDescendantElement": null,
  "HTMLLabelElement.ariaControlsElements": null,
  "HTMLLabelElement.ariaDescribedByElements": null,
  "HTMLLabelElement.ariaDetailsElements": null,
  "HTMLLabelElement.ariaErrorMessageElements": null,
  "HTMLLabelElement.ariaFlowToElements": null,
  "HTMLLabelElement.ariaLabelledByElements": null,
  "HTMLLabelElement.ariaOwnsElements": null,
  "HTMLLabelElement.firstElementChild": null,
  "HTMLLabelElement.lastElementChild": null,
  "HTMLLabelElement.previousElementSibling": null,
  "HTMLLabelElement.nextElementSibling": null,
  "HTMLLabelElement.scrollParent": null,
  "HTMLLabelElement.offsetParent": null,
  "HTMLLabelElement.form": null,
  "HTMLLabelElement.control": null,
  "HTMLLegendElement.ownerDocument": null,
  "HTMLLegendElement.parentNode": null,
  "HTMLLegendElement.parentElement": null,
  "HTMLLegendElement.childNodes": null,
  "HTMLLegendElement.firstChild": null,
  "HTMLLegendElement.lastChild": null,
  "HTMLLegendElement.previousSibling": null,
  "HTMLLegendElement.nextSibling": null,
  "HTMLLegendElement.attributes": null,
  "HTMLLegendElement.shadowRoot": null,
  "HTMLLegendElement.assignedSlot": "slot",
  "HTMLLegendElement.customElementRegistry": null,
  "HTMLLegendElement.ariaActiveDescendantElement": null,
  "HTMLLegendElement.ariaControlsElements": null,
  "HTMLLegendElement.ariaDescribedByElements": null,
  "HTMLLegendElement.ariaDetailsElements": null,
  "HTMLLegendElement.ariaErrorMessageElements": null,
  "HTMLLegendElement.ariaFlowToElements": null,
  "HTMLLegendElement.ariaLabelledByElements": null,
  "HTMLLegendElement.ariaOwnsElements": null,
  "HTMLLegendElement.firstElementChild": null,
  "HTMLLegendElement.lastElementChild": null,
  "HTMLLegendElement.previousElementSibling": null,
  "HTMLLegendElement.nextElementSibling": null,
  "HTMLLegendElement.scrollParent": null,
  "HTMLLegendElement.offsetParent": null,
  "HTMLLegendElement.form": null,
  "HTMLOptionElement.ownerDocument": null,
  "HTMLOptionElement.parentNode": null,
  "HTMLOptionElement.parentElement": null,
  "HTMLOptionElement.childNodes": null,
  "HTMLOptionElement.firstChild": null,
  "HTMLOptionElement.lastChild": null,
  "HTMLOptionElement.previousSibling": null,
  "HTMLOptionElement.nextSibling": null,
  "HTMLOptionElement.attributes": null,
  "HTMLOptionElement.shadowRoot": null,
  "HTMLOptionElement.assignedSlot": "slot",
  "HTMLOptionElement.customElementRegistry": null,
  "HTMLOptionElement.ariaActiveDescendantElement": null,
  "HTMLOptionElement.ariaControlsElements": null,
  "HTMLOptionElement.ariaDescribedByElements": null,
  "HTMLOptionElement.ariaDetailsElements": null,
  "HTMLOptionElement.ariaErrorMessageElements": null,
  "HTMLOptionElement.ariaFlowToElements": null,
  "HTMLOptionElement.ariaLabelledByElements": null,
  "HTMLOptionElement.ariaOwnsElements": null,
  "HTMLOptionElement.firstElementChild": null,
  "HTMLOptionElement.lastElementChild": null,
  "HTMLOptionElement.previousElementSibling": null,
  "HTMLOptionElement.nextElementSibling": null,
  "HTMLOptionElement.scrollParent": null,
  "HTMLOptionElement.offsetParent": null,
  "HTMLOptionElement.form": null,
  "HTMLOptGroupElement.ownerDocument": null,
  "HTMLOptGroupElement.parentNode": null,
  "HTMLOptGroupElement.parentElement": null,
  "HTMLOptGroupElement.childNodes": null,
  "HTMLOptGroupElement.firstChild": null,
  "HTMLOptGroupElement.lastChild": null,
  "HTMLOptGroupElement.previousSibling": null,
  "HTMLOptGroupElement.nextSibling": null,
  "HTMLOptGroupElement.attributes": null,
  "HTMLOptGroupElement.shadowRoot": null,
  "HTMLOptGroupElement.assignedSlot": "slot",
  "HTMLOptGroupElement.customElementRegistry": null,
  "HTMLOptGroupElement.ariaActiveDescendantElement": null,
  "HTMLOptGroupElement.ariaControlsElements": null,
  "HTMLOptGroupElement.ariaDescribedByElements": null,
  "HTMLOptGroupElement.ariaDetailsElements": null,
  "HTMLOptGroupElement.ariaErrorMessageElements": null,
  "HTMLOptGroupElement.ariaFlowToElements": null,
  "HTMLOptGroupElement.ariaLabelledByElements": null,
  "HTMLOptGroupElement.ariaOwnsElements": null,
  "HTMLOptGroupElement.firstElementChild": null,
  "HTMLOptGroupElement.lastElementChild": null,
  "HTMLOptGroupElement.previousElementSibling": null,
  "HTMLOptGroupElement.nextElementSibling": null,
  "HTMLOptGroupElement.scrollParent": null,
  "HTMLOptGroupElement.offsetParent": null,
  "HTMLOutputElement.ownerDocument": null,
  "HTMLOutputElement.parentNode": null,
  "HTMLOutputElement.parentElement": null,
  "HTMLOutputElement.childNodes": null,
  "HTMLOutputElement.firstChild": null,
  "HTMLOutputElement.lastChild": null,
  "HTMLOutputElement.previousSibling": null,
  "HTMLOutputElement.nextSibling": null,
  "HTMLOutputElement.attributes": null,
  "HTMLOutputElement.shadowRoot": null,
  "HTMLOutputElement.assignedSlot": "slot",
  "HTMLOutputElement.customElementRegistry": null,
  "HTMLOutputElement.ariaActiveDescendantElement": null,
  "HTMLOutputElement.ariaControlsElements": null,
  "HTMLOutputElement.ariaDescribedByElements": null,
  "HTMLOutputElement.ariaDetailsElements": null,
  "HTMLOutputElement.ariaErrorMessageElements": null,
  "HTMLOutputElement.ariaFlowToElements": null,
  "HTMLOutputElement.ariaLabelledByElements": null,
  "HTMLOutputElement.ariaOwnsElements": null,
  "HTMLOutputElement.firstElementChild": null,
  "HTMLOutputElement.lastElementChild": null,
  "HTMLOutputElement.previousElementSibling": null,
  "HTMLOutputElement.nextElementSibling": null,
  "HTMLOutputElement.scrollParent": null,
  "HTMLOutputElement.offsetParent": null,
  "HTMLOutputElement.form": null,
  "HTMLOutputElement.labels": null,
  "HTMLSelectedContentElement.ownerDocument": null,
  "HTMLSelectedContentElement.parentNode": null,
  "HTMLSelectedContentElement.parentElement": null,
  "HTMLSelectedContentElement.childNodes": null,
  "HTMLSelectedContentElement.firstChild": null,
  "HTMLSelectedContentElement.lastChild": null,
  "HTMLSelectedContentElement.previousSibling": null,
  "HTMLSelectedContentElement.nextSibling": null,
  "HTMLSelectedContentElement.attributes": null,
  "HTMLSelectedContentElement.shadowRoot": null,
  "HTMLSelectedContentElement.assignedSlot": "slot",
  "HTMLSelectedContentElement.customElementRegistry": null,
  "HTMLSelectedContentElement.ariaActiveDescendantElement": null,
  "HTMLSelectedContentElement.ariaControlsElements": null,
  "HTMLSelectedContentElement.ariaDescribedByElements": null,
  "HTMLSelectedContentElement.ariaDetailsElements": null,
  "HTMLSelectedContentElement.ariaErrorMessageElements": null,
  "HTMLSelectedContentElement.ariaFlowToElements": null,
  "HTMLSelectedContentElement.ariaLabelledByElements": null,
  "HTMLSelectedContentElement.ariaOwnsElements": null,
  "HTMLSelectedContentElement.firstElementChild": null,
  "HTMLSelectedContentElement.lastElementChild": null,
  "HTMLSelectedContentElement.previousElementSibling": null,
  "HTMLSelectedContentElement.nextElementSibling": null,
  "HTMLSelectedContentElement.scrollParent": null,
  "HTMLSelectedContentElement.offsetParent": null,
  "HTMLSelectElement.ownerDocument": null,
  "HTMLSelectElement.parentNode": null,
  "HTMLSelectElement.parentElement": null,
  "HTMLSelectElement.childNodes": null,
  "HTMLSelectElement.firstChild": null,
  "HTMLSelectElement.lastChild": null,
  "HTMLSelectElement.previousSibling": null,
  "HTMLSelectElement.nextSibling": null,
  "HTMLSelectElement.attributes": null,
  "HTMLSelectElement.shadowRoot": null,
  "HTMLSelectElement.assignedSlot": "slot",
  "HTMLSelectElement.customElementRegistry": null,
  "HTMLSelectElement.ariaActiveDescendantElement": null,
  "HTMLSelectElement.ariaControlsElements": null,
  "HTMLSelectElement.ariaDescribedByElements": null,
  "HTMLSelectElement.ariaDetailsElements": null,
  "HTMLSelectElement.ariaErrorMessageElements": null,
  "HTMLSelectElement.ariaFlowToElements": null,
  "HTMLSelectElement.ariaLabelledByElements": null,
  "HTMLSelectElement.ariaOwnsElements": null,
  "HTMLSelectElement.firstElementChild": null,
  "HTMLSelectElement.lastElementChild": null,
  "HTMLSelectElement.previousElementSibling": null,
  "HTMLSelectElement.nextElementSibling": null,
  "HTMLSelectElement.scrollParent": null,
  "HTMLSelectElement.offsetParent": null,
  "HTMLSelectElement.form": null,
  "HTMLSelectElement.labels": null,
  "HTMLSelectElement.selectedContentElement": "selectedcontent",
  "HTMLTextAreaElement.ownerDocument": null,
  "HTMLTextAreaElement.parentNode": null,
  "HTMLTextAreaElement.parentElement": null,
  "HTMLTextAreaElement.childNodes": null,
  "HTMLTextAreaElement.firstChild": null,
  "HTMLTextAreaElement.lastChild": null,
  "HTMLTextAreaElement.previousSibling": null,
  "HTMLTextAreaElement.nextSibling": null,
  "HTMLTextAreaElement.attributes": null,
  "HTMLTextAreaElement.shadowRoot": null,
  "HTMLTextAreaElement.assignedSlot": "slot",
  "HTMLTextAreaElement.customElementRegistry": null,
  "HTMLTextAreaElement.ariaActiveDescendantElement": null,
  "HTMLTextAreaElement.ariaControlsElements": null,
  "HTMLTextAreaElement.ariaDescribedByElements": null,
  "HTMLTextAreaElement.ariaDetailsElements": null,
  "HTMLTextAreaElement.ariaErrorMessageElements": null,
  "HTMLTextAreaElement.ariaFlowToElements": null,
  "HTMLTextAreaElement.ariaLabelledByElements": null,
  "HTMLTextAreaElement.ariaOwnsElements": null,
  "HTMLTextAreaElement.firstElementChild": null,
  "HTMLTextAreaElement.lastElementChild": null,
  "HTMLTextAreaElement.previousElementSibling": null,
  "HTMLTextAreaElement.nextElementSibling": null,
  "HTMLTextAreaElement.scrollParent": null,
  "HTMLTextAreaElement.offsetParent": null,
  "HTMLTextAreaElement.form": null,
  "HTMLTextAreaElement.labels": null,
  "SubmitEvent.submitter": null,
  "HTMLAnchorElement.ownerDocument": null,
  "HTMLAnchorElement.parentNode": null,
  "HTMLAnchorElement.parentElement": null,
  "HTMLAnchorElement.childNodes": null,
  "HTMLAnchorElement.firstChild": null,
  "HTMLAnchorElement.lastChild": null,
  "HTMLAnchorElement.previousSibling": null,
  "HTMLAnchorElement.nextSibling": null,
  "HTMLAnchorElement.attributes": null,
  "HTMLAnchorElement.shadowRoot": null,
  "HTMLAnchorElement.assignedSlot": "slot",
  "HTMLAnchorElement.customElementRegistry": null,
  "HTMLAnchorElement.ariaActiveDescendantElement": null,
  "HTMLAnchorElement.ariaControlsElements": null,
  "HTMLAnchorElement.ariaDescribedByElements": null,
  "HTMLAnchorElement.ariaDetailsElements": null,
  "HTMLAnchorElement.ariaErrorMessageElements": null,
  "HTMLAnchorElement.ariaFlowToElements": null,
  "HTMLAnchorElement.ariaLabelledByElements": null,
  "HTMLAnchorElement.ariaOwnsElements": null,
  "HTMLAnchorElement.firstElementChild": null,
  "HTMLAnchorElement.lastElementChild": null,
  "HTMLAnchorElement.previousElementSibling": null,
  "HTMLAnchorElement.nextElementSibling": null,
  "HTMLAnchorElement.scrollParent": null,
  "HTMLAnchorElement.offsetParent": null,
  "HTMLAnchorElement.interestForElement": null,
  "HTMLAreaElement.ownerDocument": null,
  "HTMLAreaElement.parentNode": null,
  "HTMLAreaElement.parentElement": null,
  "HTMLAreaElement.childNodes": null,
  "HTMLAreaElement.firstChild": null,
  "HTMLAreaElement.lastChild": null,
  "HTMLAreaElement.previousSibling": null,
  "HTMLAreaElement.nextSibling": null,
  "HTMLAreaElement.attributes": null,
  "HTMLAreaElement.shadowRoot": null,
  "HTMLAreaElement.assignedSlot": "slot",
  "HTMLAreaElement.customElementRegistry": null,
  "HTMLAreaElement.ariaActiveDescendantElement": null,
  "HTMLAreaElement.ariaControlsElements": null,
  "HTMLAreaElement.ariaDescribedByElements": null,
  "HTMLAreaElement.ariaDetailsElements": null,
  "HTMLAreaElement.ariaErrorMessageElements": null,
  "HTMLAreaElement.ariaFlowToElements": null,
  "HTMLAreaElement.ariaLabelledByElements": null,
  "HTMLAreaElement.ariaOwnsElements": null,
  "HTMLAreaElement.firstElementChild": null,
  "HTMLAreaElement.lastElementChild": null,
  "HTMLAreaElement.previousElementSibling": null,
  "HTMLAreaElement.nextElementSibling": null,
  "HTMLAreaElement.scrollParent": null,
  "HTMLAreaElement.offsetParent": null,
  "HTMLAreaElement.interestForElement": null,
  "HTMLBaseElement.ownerDocument": null,
  "HTMLBaseElement.parentNode": null,
  "HTMLBaseElement.parentElement": null,
  "HTMLBaseElement.childNodes": null,
  "HTMLBaseElement.firstChild": null,
  "HTMLBaseElement.lastChild": null,
  "HTMLBaseElement.previousSibling": null,
  "HTMLBaseElement.nextSibling": null,
  "HTMLBaseElement.attributes": null,
  "HTMLBaseElement.shadowRoot": null,
  "HTMLBaseElement.assignedSlot": "slot",
  "HTMLBaseElement.customElementRegistry": null,
  "HTMLBaseElement.ariaActiveDescendantElement": null,
  "HTMLBaseElement.ariaControlsElements": null,
  "HTMLBaseElement.ariaDescribedByElements": null,
  "HTMLBaseElement.ariaDetailsElements": null,
  "HTMLBaseElement.ariaErrorMessageElements": null,
  "HTMLBaseElement.ariaFlowToElements": null,
  "HTMLBaseElement.ariaLabelledByElements": null,
  "HTMLBaseElement.ariaOwnsElements": null,
  "HTMLBaseElement.firstElementChild": null,
  "HTMLBaseElement.lastElementChild": null,
  "HTMLBaseElement.previousElementSibling": null,
  "HTMLBaseElement.nextElementSibling": null,
  "HTMLBaseElement.scrollParent": null,
  "HTMLBaseElement.offsetParent": null,
  "HTMLBodyElement.ownerDocument": null,
  "HTMLBodyElement.parentNode": null,
  "HTMLBodyElement.parentElement": null,
  "HTMLBodyElement.childNodes": null,
  "HTMLBodyElement.firstChild": null,
  "HTMLBodyElement.lastChild": null,
  "HTMLBodyElement.previousSibling": null,
  "HTMLBodyElement.nextSibling": null,
  "HTMLBodyElement.attributes": null,
  "HTMLBodyElement.shadowRoot": null,
  "HTMLBodyElement.assignedSlot": "slot",
  "HTMLBodyElement.customElementRegistry": null,
  "HTMLBodyElement.ariaActiveDescendantElement": null,
  "HTMLBodyElement.ariaControlsElements": null,
  "HTMLBodyElement.ariaDescribedByElements": null,
  "HTMLBodyElement.ariaDetailsElements": null,
  "HTMLBodyElement.ariaErrorMessageElements": null,
  "HTMLBodyElement.ariaFlowToElements": null,
  "HTMLBodyElement.ariaLabelledByElements": null,
  "HTMLBodyElement.ariaOwnsElements": null,
  "HTMLBodyElement.firstElementChild": null,
  "HTMLBodyElement.lastElementChild": null,
  "HTMLBodyElement.previousElementSibling": null,
  "HTMLBodyElement.nextElementSibling": null,
  "HTMLBodyElement.scrollParent": null,
  "HTMLBodyElement.offsetParent": null,
  "HTMLBRElement.ownerDocument": null,
  "HTMLBRElement.parentNode": null,
  "HTMLBRElement.parentElement": null,
  "HTMLBRElement.childNodes": null,
  "HTMLBRElement.firstChild": null,
  "HTMLBRElement.lastChild": null,
  "HTMLBRElement.previousSibling": null,
  "HTMLBRElement.nextSibling": null,
  "HTMLBRElement.attributes": null,
  "HTMLBRElement.shadowRoot": null,
  "HTMLBRElement.assignedSlot": "slot",
  "HTMLBRElement.customElementRegistry": null,
  "HTMLBRElement.ariaActiveDescendantElement": null,
  "HTMLBRElement.ariaControlsElements": null,
  "HTMLBRElement.ariaDescribedByElements": null,
  "HTMLBRElement.ariaDetailsElements": null,
  "HTMLBRElement.ariaErrorMessageElements": null,
  "HTMLBRElement.ariaFlowToElements": null,
  "HTMLBRElement.ariaLabelledByElements": null,
  "HTMLBRElement.ariaOwnsElements": null,
  "HTMLBRElement.firstElementChild": null,
  "HTMLBRElement.lastElementChild": null,
  "HTMLBRElement.previousElementSibling": null,
  "HTMLBRElement.nextElementSibling": null,
  "HTMLBRElement.scrollParent": null,
  "HTMLBRElement.offsetParent": null,
  "HTMLCredentialElement.ownerDocument": null,
  "HTMLCredentialElement.parentNode": null,
  "HTMLCredentialElement.parentElement": null,
  "HTMLCredentialElement.childNodes": null,
  "HTMLCredentialElement.firstChild": null,
  "HTMLCredentialElement.lastChild": null,
  "HTMLCredentialElement.previousSibling": null,
  "HTMLCredentialElement.nextSibling": null,
  "HTMLCredentialElement.attributes": null,
  "HTMLCredentialElement.shadowRoot": null,
  "HTMLCredentialElement.assignedSlot": "slot",
  "HTMLCredentialElement.customElementRegistry": null,
  "HTMLCredentialElement.ariaActiveDescendantElement": null,
  "HTMLCredentialElement.ariaControlsElements": null,
  "HTMLCredentialElement.ariaDescribedByElements": null,
  "HTMLCredentialElement.ariaDetailsElements": null,
  "HTMLCredentialElement.ariaErrorMessageElements": null,
  "HTMLCredentialElement.ariaFlowToElements": null,
  "HTMLCredentialElement.ariaLabelledByElements": null,
  "HTMLCredentialElement.ariaOwnsElements": null,
  "HTMLCredentialElement.firstElementChild": null,
  "HTMLCredentialElement.lastElementChild": null,
  "HTMLCredentialElement.previousElementSibling": null,
  "HTMLCredentialElement.nextElementSibling": null,
  "HTMLCredentialElement.scrollParent": null,
  "HTMLCredentialElement.offsetParent": null,
  "HTMLDataElement.ownerDocument": null,
  "HTMLDataElement.parentNode": null,
  "HTMLDataElement.parentElement": null,
  "HTMLDataElement.childNodes": null,
  "HTMLDataElement.firstChild": null,
  "HTMLDataElement.lastChild": null,
  "HTMLDataElement.previousSibling": null,
  "HTMLDataElement.nextSibling": null,
  "HTMLDataElement.attributes": null,
  "HTMLDataElement.shadowRoot": null,
  "HTMLDataElement.assignedSlot": "slot",
  "HTMLDataElement.customElementRegistry": null,
  "HTMLDataElement.ariaActiveDescendantElement": null,
  "HTMLDataElement.ariaControlsElements": null,
  "HTMLDataElement.ariaDescribedByElements": null,
  "HTMLDataElement.ariaDetailsElements": null,
  "HTMLDataElement.ariaErrorMessageElements": null,
  "HTMLDataElement.ariaFlowToElements": null,
  "HTMLDataElement.ariaLabelledByElements": null,
  "HTMLDataElement.ariaOwnsElements": null,
  "HTMLDataElement.firstElementChild": null,
  "HTMLDataElement.lastElementChild": null,
  "HTMLDataElement.previousElementSibling": null,
  "HTMLDataElement.nextElementSibling": null,
  "HTMLDataElement.scrollParent": null,
  "HTMLDataElement.offsetParent": null,
  "HTMLDetailsElement.ownerDocument": null,
  "HTMLDetailsElement.parentNode": null,
  "HTMLDetailsElement.parentElement": null,
  "HTMLDetailsElement.childNodes": null,
  "HTMLDetailsElement.firstChild": null,
  "HTMLDetailsElement.lastChild": null,
  "HTMLDetailsElement.previousSibling": null,
  "HTMLDetailsElement.nextSibling": null,
  "HTMLDetailsElement.attributes": null,
  "HTMLDetailsElement.shadowRoot": null,
  "HTMLDetailsElement.assignedSlot": "slot",
  "HTMLDetailsElement.customElementRegistry": null,
  "HTMLDetailsElement.ariaActiveDescendantElement": null,
  "HTMLDetailsElement.ariaControlsElements": null,
  "HTMLDetailsElement.ariaDescribedByElements": null,
  "HTMLDetailsElement.ariaDetailsElements": null,
  "HTMLDetailsElement.ariaErrorMessageElements": null,
  "HTMLDetailsElement.ariaFlowToElements": null,
  "HTMLDetailsElement.ariaLabelledByElements": null,
  "HTMLDetailsElement.ariaOwnsElements": null,
  "HTMLDetailsElement.firstElementChild": null,
  "HTMLDetailsElement.lastElementChild": null,
  "HTMLDetailsElement.previousElementSibling": null,
  "HTMLDetailsElement.nextElementSibling": null,
  "HTMLDetailsElement.scrollParent": null,
  "HTMLDetailsElement.offsetParent": null,
  "HTMLDialogElement.ownerDocument": null,
  "HTMLDialogElement.parentNode": null,
  "HTMLDialogElement.parentElement": null,
  "HTMLDialogElement.childNodes": null,
  "HTMLDialogElement.firstChild": null,
  "HTMLDialogElement.lastChild": null,
  "HTMLDialogElement.previousSibling": null,
  "HTMLDialogElement.nextSibling": null,
  "HTMLDialogElement.attributes": null,
  "HTMLDialogElement.shadowRoot": null,
  "HTMLDialogElement.assignedSlot": "slot",
  "HTMLDialogElement.customElementRegistry": null,
  "HTMLDialogElement.ariaActiveDescendantElement": null,
  "HTMLDialogElement.ariaControlsElements": null,
  "HTMLDialogElement.ariaDescribedByElements": null,
  "HTMLDialogElement.ariaDetailsElements": null,
  "HTMLDialogElement.ariaErrorMessageElements": null,
  "HTMLDialogElement.ariaFlowToElements": null,
  "HTMLDialogElement.ariaLabelledByElements": null,
  "HTMLDialogElement.ariaOwnsElements": null,
  "HTMLDialogElement.firstElementChild": null,
  "HTMLDialogElement.lastElementChild": null,
  "HTMLDialogElement.previousElementSibling": null,
  "HTMLDialogElement.nextElementSibling": null,
  "HTMLDialogElement.scrollParent": null,
  "HTMLDialogElement.offsetParent": null,
  "HTMLDirectoryElement.ownerDocument": null,
  "HTMLDirectoryElement.parentNode": null,
  "HTMLDirectoryElement.parentElement": null,
  "HTMLDirectoryElement.childNodes": null,
  "HTMLDirectoryElement.firstChild": null,
  "HTMLDirectoryElement.lastChild": null,
  "HTMLDirectoryElement.previousSibling": null,
  "HTMLDirectoryElement.nextSibling": null,
  "HTMLDirectoryElement.attributes": null,
  "HTMLDirectoryElement.shadowRoot": null,
  "HTMLDirectoryElement.assignedSlot": "slot",
  "HTMLDirectoryElement.customElementRegistry": null,
  "HTMLDirectoryElement.ariaActiveDescendantElement": null,
  "HTMLDirectoryElement.ariaControlsElements": null,
  "HTMLDirectoryElement.ariaDescribedByElements": null,
  "HTMLDirectoryElement.ariaDetailsElements": null,
  "HTMLDirectoryElement.ariaErrorMessageElements": null,
  "HTMLDirectoryElement.ariaFlowToElements": null,
  "HTMLDirectoryElement.ariaLabelledByElements": null,
  "HTMLDirectoryElement.ariaOwnsElements": null,
  "HTMLDirectoryElement.firstElementChild": null,
  "HTMLDirectoryElement.lastElementChild": null,
  "HTMLDirectoryElement.previousElementSibling": null,
  "HTMLDirectoryElement.nextElementSibling": null,
  "HTMLDirectoryElement.scrollParent": null,
  "HTMLDirectoryElement.offsetParent": null,
  "HTMLDivElement.ownerDocument": null,
  "HTMLDivElement.parentNode": null,
  "HTMLDivElement.parentElement": null,
  "HTMLDivElement.childNodes": null,
  "HTMLDivElement.firstChild": null,
  "HTMLDivElement.lastChild": null,
  "HTMLDivElement.previousSibling": null,
  "HTMLDivElement.nextSibling": null,
  "HTMLDivElement.attributes": null,
  "HTMLDivElement.shadowRoot": null,
  "HTMLDivElement.assignedSlot": "slot",
  "HTMLDivElement.customElementRegistry": null,
  "HTMLDivElement.ariaActiveDescendantElement": null,
  "HTMLDivElement.ariaControlsElements": null,
  "HTMLDivElement.ariaDescribedByElements": null,
  "HTMLDivElement.ariaDetailsElements": null,
  "HTMLDivElement.ariaErrorMessageElements": null,
  "HTMLDivElement.ariaFlowToElements": null,
  "HTMLDivElement.ariaLabelledByElements": null,
  "HTMLDivElement.ariaOwnsElements": null,
  "HTMLDivElement.firstElementChild": null,
  "HTMLDivElement.lastElementChild": null,
  "HTMLDivElement.previousElementSibling": null,
  "HTMLDivElement.nextElementSibling": null,
  "HTMLDivElement.scrollParent": null,
  "HTMLDivElement.offsetParent": null,
  "HTMLDListElement.ownerDocument": null,
  "HTMLDListElement.parentNode": null,
  "HTMLDListElement.parentElement": null,
  "HTMLDListElement.childNodes": null,
  "HTMLDListElement.firstChild": null,
  "HTMLDListElement.lastChild": null,
  "HTMLDListElement.previousSibling": null,
  "HTMLDListElement.nextSibling": null,
  "HTMLDListElement.attributes": null,
  "HTMLDListElement.shadowRoot": null,
  "HTMLDListElement.assignedSlot": "slot",
  "HTMLDListElement.customElementRegistry": null,
  "HTMLDListElement.ariaActiveDescendantElement": null,
  "HTMLDListElement.ariaControlsElements": null,
  "HTMLDListElement.ariaDescribedByElements": null,
  "HTMLDListElement.ariaDetailsElements": null,
  "HTMLDListElement.ariaErrorMessageElements": null,
  "HTMLDListElement.ariaFlowToElements": null,
  "HTMLDListElement.ariaLabelledByElements": null,
  "HTMLDListElement.ariaOwnsElements": null,
  "HTMLDListElement.firstElementChild": null,
  "HTMLDListElement.lastElementChild": null,
  "HTMLDListElement.previousElementSibling": null,
  "HTMLDListElement.nextElementSibling": null,
  "HTMLDListElement.scrollParent": null,
  "HTMLDListElement.offsetParent": null,
  "HTMLDocument.ownerDocument": null,
  "HTMLDocument.parentNode": null,
  "HTMLDocument.parentElement": null,
  "HTMLDocument.childNodes": null,
  "HTMLDocument.firstChild": null,
  "HTMLDocument.lastChild": null,
  "HTMLDocument.previousSibling": null,
  "HTMLDocument.nextSibling": null,
  "HTMLDocument.doctype": null,
  "HTMLDocument.documentElement": null,
  "HTMLDocument.body": null,
  "HTMLDocument.head": "head",
  "HTMLDocument.scrollingElement": null,
  "HTMLDocument.webkitCurrentFullScreenElement": null,
  "HTMLDocument.webkitFullscreenElement": null,
  "HTMLDocument.rootElement": null,
  "HTMLDocument.firstElementChild": null,
  "HTMLDocument.lastElementChild": null,
  "HTMLDocument.activeElement": null,
  "HTMLDocument.pointerLockElement": null,
  "HTMLDocument.fullscreenElement": null,
  "HTMLDocument.pictureInPictureElement": null,
  "HTMLDocument.customElementRegistry": null,
  "HTMLElement.ownerDocument": null,
  "HTMLElement.parentNode": null,
  "HTMLElement.parentElement": null,
  "HTMLElement.childNodes": null,
  "HTMLElement.firstChild": null,
  "HTMLElement.lastChild": null,
  "HTMLElement.previousSibling": null,
  "HTMLElement.nextSibling": null,
  "HTMLElement.attributes": null,
  "HTMLElement.shadowRoot": null,
  "HTMLElement.assignedSlot": "slot",
  "HTMLElement.customElementRegistry": null,
  "HTMLElement.ariaActiveDescendantElement": null,
  "HTMLElement.ariaControlsElements": null,
  "HTMLElement.ariaDescribedByElements": null,
  "HTMLElement.ariaDetailsElements": null,
  "HTMLElement.ariaErrorMessageElements": null,
  "HTMLElement.ariaFlowToElements": null,
  "HTMLElement.ariaLabelledByElements": null,
  "HTMLElement.ariaOwnsElements": null,
  "HTMLElement.firstElementChild": null,
  "HTMLElement.lastElementChild": null,
  "HTMLElement.previousElementSibling": null,
  "HTMLElement.nextElementSibling": null,
  "HTMLElement.scrollParent": null,
  "HTMLElement.offsetParent": null,
  "HTMLEmbedElement.ownerDocument": null,
  "HTMLEmbedElement.parentNode": null,
  "HTMLEmbedElement.parentElement": null,
  "HTMLEmbedElement.childNodes": null,
  "HTMLEmbedElement.firstChild": null,
  "HTMLEmbedElement.lastChild": null,
  "HTMLEmbedElement.previousSibling": null,
  "HTMLEmbedElement.nextSibling": null,
  "HTMLEmbedElement.attributes": null,
  "HTMLEmbedElement.shadowRoot": null,
  "HTMLEmbedElement.assignedSlot": "slot",
  "HTMLEmbedElement.customElementRegistry": null,
  "HTMLEmbedElement.ariaActiveDescendantElement": null,
  "HTMLEmbedElement.ariaControlsElements": null,
  "HTMLEmbedElement.ariaDescribedByElements": null,
  "HTMLEmbedElement.ariaDetailsElements": null,
  "HTMLEmbedElement.ariaErrorMessageElements": null,
  "HTMLEmbedElement.ariaFlowToElements": null,
  "HTMLEmbedElement.ariaLabelledByElements": null,
  "HTMLEmbedElement.ariaOwnsElements": null,
  "HTMLEmbedElement.firstElementChild": null,
  "HTMLEmbedElement.lastElementChild": null,
  "HTMLEmbedElement.previousElementSibling": null,
  "HTMLEmbedElement.nextElementSibling": null,
  "HTMLEmbedElement.scrollParent": null,
  "HTMLEmbedElement.offsetParent": null,
  "HTMLFontElement.ownerDocument": null,
  "HTMLFontElement.parentNode": null,
  "HTMLFontElement.parentElement": null,
  "HTMLFontElement.childNodes": null,
  "HTMLFontElement.firstChild": null,
  "HTMLFontElement.lastChild": null,
  "HTMLFontElement.previousSibling": null,
  "HTMLFontElement.nextSibling": null,
  "HTMLFontElement.attributes": null,
  "HTMLFontElement.shadowRoot": null,
  "HTMLFontElement.assignedSlot": "slot",
  "HTMLFontElement.customElementRegistry": null,
  "HTMLFontElement.ariaActiveDescendantElement": null,
  "HTMLFontElement.ariaControlsElements": null,
  "HTMLFontElement.ariaDescribedByElements": null,
  "HTMLFontElement.ariaDetailsElements": null,
  "HTMLFontElement.ariaErrorMessageElements": null,
  "HTMLFontElement.ariaFlowToElements": null,
  "HTMLFontElement.ariaLabelledByElements": null,
  "HTMLFontElement.ariaOwnsElements": null,
  "HTMLFontElement.firstElementChild": null,
  "HTMLFontElement.lastElementChild": null,
  "HTMLFontElement.previousElementSibling": null,
  "HTMLFontElement.nextElementSibling": null,
  "HTMLFontElement.scrollParent": null,
  "HTMLFontElement.offsetParent": null,
  "HTMLFrameElement.ownerDocument": null,
  "HTMLFrameElement.parentNode": null,
  "HTMLFrameElement.parentElement": null,
  "HTMLFrameElement.childNodes": null,
  "HTMLFrameElement.firstChild": null,
  "HTMLFrameElement.lastChild": null,
  "HTMLFrameElement.previousSibling": null,
  "HTMLFrameElement.nextSibling": null,
  "HTMLFrameElement.attributes": null,
  "HTMLFrameElement.shadowRoot": null,
  "HTMLFrameElement.assignedSlot": "slot",
  "HTMLFrameElement.customElementRegistry": null,
  "HTMLFrameElement.ariaActiveDescendantElement": null,
  "HTMLFrameElement.ariaControlsElements": null,
  "HTMLFrameElement.ariaDescribedByElements": null,
  "HTMLFrameElement.ariaDetailsElements": null,
  "HTMLFrameElement.ariaErrorMessageElements": null,
  "HTMLFrameElement.ariaFlowToElements": null,
  "HTMLFrameElement.ariaLabelledByElements": null,
  "HTMLFrameElement.ariaOwnsElements": null,
  "HTMLFrameElement.firstElementChild": null,
  "HTMLFrameElement.lastElementChild": null,
  "HTMLFrameElement.previousElementSibling": null,
  "HTMLFrameElement.nextElementSibling": null,
  "HTMLFrameElement.scrollParent": null,
  "HTMLFrameElement.offsetParent": null,
  "HTMLFrameElement.contentDocument": null,
  "HTMLFrameSetElement.ownerDocument": null,
  "HTMLFrameSetElement.parentNode": null,
  "HTMLFrameSetElement.parentElement": null,
  "HTMLFrameSetElement.childNodes": null,
  "HTMLFrameSetElement.firstChild": null,
  "HTMLFrameSetElement.lastChild": null,
  "HTMLFrameSetElement.previousSibling": null,
  "HTMLFrameSetElement.nextSibling": null,
  "HTMLFrameSetElement.attributes": null,
  "HTMLFrameSetElement.shadowRoot": null,
  "HTMLFrameSetElement.assignedSlot": "slot",
  "HTMLFrameSetElement.customElementRegistry": null,
  "HTMLFrameSetElement.ariaActiveDescendantElement": null,
  "HTMLFrameSetElement.ariaControlsElements": null,
  "HTMLFrameSetElement.ariaDescribedByElements": null,
  "HTMLFrameSetElement.ariaDetailsElements": null,
  "HTMLFrameSetElement.ariaErrorMessageElements": null,
  "HTMLFrameSetElement.ariaFlowToElements": null,
  "HTMLFrameSetElement.ariaLabelledByElements": null,
  "HTMLFrameSetElement.ariaOwnsElements": null,
  "HTMLFrameSetElement.firstElementChild": null,
  "HTMLFrameSetElement.lastElementChild": null,
  "HTMLFrameSetElement.previousElementSibling": null,
  "HTMLFrameSetElement.nextElementSibling": null,
  "HTMLFrameSetElement.scrollParent": null,
  "HTMLFrameSetElement.offsetParent": null,
  "HTMLGeolocationElement.ownerDocument": null,
  "HTMLGeolocationElement.parentNode": null,
  "HTMLGeolocationElement.parentElement": null,
  "HTMLGeolocationElement.childNodes": null,
  "HTMLGeolocationElement.firstChild": null,
  "HTMLGeolocationElement.lastChild": null,
  "HTMLGeolocationElement.previousSibling": null,
  "HTMLGeolocationElement.nextSibling": null,
  "HTMLGeolocationElement.attributes": null,
  "HTMLGeolocationElement.shadowRoot": null,
  "HTMLGeolocationElement.assignedSlot": "slot",
  "HTMLGeolocationElement.customElementRegistry": null,
  "HTMLGeolocationElement.ariaActiveDescendantElement": null,
  "HTMLGeolocationElement.ariaControlsElements": null,
  "HTMLGeolocationElement.ariaDescribedByElements": null,
  "HTMLGeolocationElement.ariaDetailsElements": null,
  "HTMLGeolocationElement.ariaErrorMessageElements": null,
  "HTMLGeolocationElement.ariaFlowToElements": null,
  "HTMLGeolocationElement.ariaLabelledByElements": null,
  "HTMLGeolocationElement.ariaOwnsElements": null,
  "HTMLGeolocationElement.firstElementChild": null,
  "HTMLGeolocationElement.lastElementChild": null,
  "HTMLGeolocationElement.previousElementSibling": null,
  "HTMLGeolocationElement.nextElementSibling": null,
  "HTMLGeolocationElement.scrollParent": null,
  "HTMLGeolocationElement.offsetParent": null,
  "HTMLHeadingElement.ownerDocument": null,
  "HTMLHeadingElement.parentNode": null,
  "HTMLHeadingElement.parentElement": null,
  "HTMLHeadingElement.childNodes": null,
  "HTMLHeadingElement.firstChild": null,
  "HTMLHeadingElement.lastChild": null,
  "HTMLHeadingElement.previousSibling": null,
  "HTMLHeadingElement.nextSibling": null,
  "HTMLHeadingElement.attributes": null,
  "HTMLHeadingElement.shadowRoot": null,
  "HTMLHeadingElement.assignedSlot": "slot",
  "HTMLHeadingElement.customElementRegistry": null,
  "HTMLHeadingElement.ariaActiveDescendantElement": null,
  "HTMLHeadingElement.ariaControlsElements": null,
  "HTMLHeadingElement.ariaDescribedByElements": null,
  "HTMLHeadingElement.ariaDetailsElements": null,
  "HTMLHeadingElement.ariaErrorMessageElements": null,
  "HTMLHeadingElement.ariaFlowToElements": null,
  "HTMLHeadingElement.ariaLabelledByElements": null,
  "HTMLHeadingElement.ariaOwnsElements": null,
  "HTMLHeadingElement.firstElementChild": null,
  "HTMLHeadingElement.lastElementChild": null,
  "HTMLHeadingElement.previousElementSibling": null,
  "HTMLHeadingElement.nextElementSibling": null,
  "HTMLHeadingElement.scrollParent": null,
  "HTMLHeadingElement.offsetParent": null,
  "HTMLHeadElement.ownerDocument": null,
  "HTMLHeadElement.parentNode": null,
  "HTMLHeadElement.parentElement": null,
  "HTMLHeadElement.childNodes": null,
  "HTMLHeadElement.firstChild": null,
  "HTMLHeadElement.lastChild": null,
  "HTMLHeadElement.previousSibling": null,
  "HTMLHeadElement.nextSibling": null,
  "HTMLHeadElement.attributes": null,
  "HTMLHeadElement.shadowRoot": null,
  "HTMLHeadElement.assignedSlot": "slot",
  "HTMLHeadElement.customElementRegistry": null,
  "HTMLHeadElement.ariaActiveDescendantElement": null,
  "HTMLHeadElement.ariaControlsElements": null,
  "HTMLHeadElement.ariaDescribedByElements": null,
  "HTMLHeadElement.ariaDetailsElements": null,
  "HTMLHeadElement.ariaErrorMessageElements": null,
  "HTMLHeadElement.ariaFlowToElements": null,
  "HTMLHeadElement.ariaLabelledByElements": null,
  "HTMLHeadElement.ariaOwnsElements": null,
  "HTMLHeadElement.firstElementChild": null,
  "HTMLHeadElement.lastElementChild": null,
  "HTMLHeadElement.previousElementSibling": null,
  "HTMLHeadElement.nextElementSibling": null,
  "HTMLHeadElement.scrollParent": null,
  "HTMLHeadElement.offsetParent": null,
  "HTMLHRElement.ownerDocument": null,
  "HTMLHRElement.parentNode": null,
  "HTMLHRElement.parentElement": null,
  "HTMLHRElement.childNodes": null,
  "HTMLHRElement.firstChild": null,
  "HTMLHRElement.lastChild": null,
  "HTMLHRElement.previousSibling": null,
  "HTMLHRElement.nextSibling": null,
  "HTMLHRElement.attributes": null,
  "HTMLHRElement.shadowRoot": null,
  "HTMLHRElement.assignedSlot": "slot",
  "HTMLHRElement.customElementRegistry": null,
  "HTMLHRElement.ariaActiveDescendantElement": null,
  "HTMLHRElement.ariaControlsElements": null,
  "HTMLHRElement.ariaDescribedByElements": null,
  "HTMLHRElement.ariaDetailsElements": null,
  "HTMLHRElement.ariaErrorMessageElements": null,
  "HTMLHRElement.ariaFlowToElements": null,
  "HTMLHRElement.ariaLabelledByElements": null,
  "HTMLHRElement.ariaOwnsElements": null,
  "HTMLHRElement.firstElementChild": null,
  "HTMLHRElement.lastElementChild": null,
  "HTMLHRElement.previousElementSibling": null,
  "HTMLHRElement.nextElementSibling": null,
  "HTMLHRElement.scrollParent": null,
  "HTMLHRElement.offsetParent": null,
  "HTMLHtmlElement.ownerDocument": null,
  "HTMLHtmlElement.parentNode": null,
  "HTMLHtmlElement.parentElement": null,
  "HTMLHtmlElement.childNodes": null,
  "HTMLHtmlElement.firstChild": null,
  "HTMLHtmlElement.lastChild": null,
  "HTMLHtmlElement.previousSibling": null,
  "HTMLHtmlElement.nextSibling": null,
  "HTMLHtmlElement.attributes": null,
  "HTMLHtmlElement.shadowRoot": null,
  "HTMLHtmlElement.assignedSlot": "slot",
  "HTMLHtmlElement.customElementRegistry": null,
  "HTMLHtmlElement.ariaActiveDescendantElement": null,
  "HTMLHtmlElement.ariaControlsElements": null,
  "HTMLHtmlElement.ariaDescribedByElements": null,
  "HTMLHtmlElement.ariaDetailsElements": null,
  "HTMLHtmlElement.ariaErrorMessageElements": null,
  "HTMLHtmlElement.ariaFlowToElements": null,
  "HTMLHtmlElement.ariaLabelledByElements": null,
  "HTMLHtmlElement.ariaOwnsElements": null,
  "HTMLHtmlElement.firstElementChild": null,
  "HTMLHtmlElement.lastElementChild": null,
  "HTMLHtmlElement.previousElementSibling": null,
  "HTMLHtmlElement.nextElementSibling": null,
  "HTMLHtmlElement.scrollParent": null,
  "HTMLHtmlElement.offsetParent": null,
  "HTMLIFrameElement.ownerDocument": null,
  "HTMLIFrameElement.parentNode": null,
  "HTMLIFrameElement.parentElement": null,
  "HTMLIFrameElement.childNodes": null,
  "HTMLIFrameElement.firstChild": null,
  "HTMLIFrameElement.lastChild": null,
  "HTMLIFrameElement.previousSibling": null,
  "HTMLIFrameElement.nextSibling": null,
  "HTMLIFrameElement.attributes": null,
  "HTMLIFrameElement.shadowRoot": null,
  "HTMLIFrameElement.assignedSlot": "slot",
  "HTMLIFrameElement.customElementRegistry": null,
  "HTMLIFrameElement.ariaActiveDescendantElement": null,
  "HTMLIFrameElement.ariaControlsElements": null,
  "HTMLIFrameElement.ariaDescribedByElements": null,
  "HTMLIFrameElement.ariaDetailsElements": null,
  "HTMLIFrameElement.ariaErrorMessageElements": null,
  "HTMLIFrameElement.ariaFlowToElements": null,
  "HTMLIFrameElement.ariaLabelledByElements": null,
  "HTMLIFrameElement.ariaOwnsElements": null,
  "HTMLIFrameElement.firstElementChild": null,
  "HTMLIFrameElement.lastElementChild": null,
  "HTMLIFrameElement.previousElementSibling": null,
  "HTMLIFrameElement.nextElementSibling": null,
  "HTMLIFrameElement.scrollParent": null,
  "HTMLIFrameElement.offsetParent": null,
  "HTMLIFrameElement.contentDocument": null,
  "HTMLImageElement.ownerDocument": null,
  "HTMLImageElement.parentNode": null,
  "HTMLImageElement.parentElement": null,
  "HTMLImageElement.childNodes": null,
  "HTMLImageElement.firstChild": null,
  "HTMLImageElement.lastChild": null,
  "HTMLImageElement.previousSibling": null,
  "HTMLImageElement.nextSibling": null,
  "HTMLImageElement.attributes": null,
  "HTMLImageElement.shadowRoot": null,
  "HTMLImageElement.assignedSlot": "slot",
  "HTMLImageElement.customElementRegistry": null,
  "HTMLImageElement.ariaActiveDescendantElement": null,
  "HTMLImageElement.ariaControlsElements": null,
  "HTMLImageElement.ariaDescribedByElements": null,
  "HTMLImageElement.ariaDetailsElements": null,
  "HTMLImageElement.ariaErrorMessageElements": null,
  "HTMLImageElement.ariaFlowToElements": null,
  "HTMLImageElement.ariaLabelledByElements": null,
  "HTMLImageElement.ariaOwnsElements": null,
  "HTMLImageElement.firstElementChild": null,
  "HTMLImageElement.lastElementChild": null,
  "HTMLImageElement.previousElementSibling": null,
  "HTMLImageElement.nextElementSibling": null,
  "HTMLImageElement.scrollParent": null,
  "HTMLImageElement.offsetParent": null,
  "HTMLInstallElement.ownerDocument": null,
  "HTMLInstallElement.parentNode": null,
  "HTMLInstallElement.parentElement": null,
  "HTMLInstallElement.childNodes": null,
  "HTMLInstallElement.firstChild": null,
  "HTMLInstallElement.lastChild": null,
  "HTMLInstallElement.previousSibling": null,
  "HTMLInstallElement.nextSibling": null,
  "HTMLInstallElement.attributes": null,
  "HTMLInstallElement.shadowRoot": null,
  "HTMLInstallElement.assignedSlot": "slot",
  "HTMLInstallElement.customElementRegistry": null,
  "HTMLInstallElement.ariaActiveDescendantElement": null,
  "HTMLInstallElement.ariaControlsElements": null,
  "HTMLInstallElement.ariaDescribedByElements": null,
  "HTMLInstallElement.ariaDetailsElements": null,
  "HTMLInstallElement.ariaErrorMessageElements": null,
  "HTMLInstallElement.ariaFlowToElements": null,
  "HTMLInstallElement.ariaLabelledByElements": null,
  "HTMLInstallElement.ariaOwnsElements": null,
  "HTMLInstallElement.firstElementChild": null,
  "HTMLInstallElement.lastElementChild": null,
  "HTMLInstallElement.previousElementSibling": null,
  "HTMLInstallElement.nextElementSibling": null,
  "HTMLInstallElement.scrollParent": null,
  "HTMLInstallElement.offsetParent": null,
  "HTMLLinkElement.ownerDocument": null,
  "HTMLLinkElement.parentNode": null,
  "HTMLLinkElement.parentElement": null,
  "HTMLLinkElement.childNodes": null,
  "HTMLLinkElement.firstChild": null,
  "HTMLLinkElement.lastChild": null,
  "HTMLLinkElement.previousSibling": null,
  "HTMLLinkElement.nextSibling": null,
  "HTMLLinkElement.attributes": null,
  "HTMLLinkElement.shadowRoot": null,
  "HTMLLinkElement.assignedSlot": "slot",
  "HTMLLinkElement.customElementRegistry": null,
  "HTMLLinkElement.ariaActiveDescendantElement": null,
  "HTMLLinkElement.ariaControlsElements": null,
  "HTMLLinkElement.ariaDescribedByElements": null,
  "HTMLLinkElement.ariaDetailsElements": null,
  "HTMLLinkElement.ariaErrorMessageElements": null,
  "HTMLLinkElement.ariaFlowToElements": null,
  "HTMLLinkElement.ariaLabelledByElements": null,
  "HTMLLinkElement.ariaOwnsElements": null,
  "HTMLLinkElement.firstElementChild": null,
  "HTMLLinkElement.lastElementChild": null,
  "HTMLLinkElement.previousElementSibling": null,
  "HTMLLinkElement.nextElementSibling": null,
  "HTMLLinkElement.scrollParent": null,
  "HTMLLinkElement.offsetParent": null,
  "HTMLLIElement.ownerDocument": null,
  "HTMLLIElement.parentNode": null,
  "HTMLLIElement.parentElement": null,
  "HTMLLIElement.childNodes": null,
  "HTMLLIElement.firstChild": null,
  "HTMLLIElement.lastChild": null,
  "HTMLLIElement.previousSibling": null,
  "HTMLLIElement.nextSibling": null,
  "HTMLLIElement.attributes": null,
  "HTMLLIElement.shadowRoot": null,
  "HTMLLIElement.assignedSlot": "slot",
  "HTMLLIElement.customElementRegistry": null,
  "HTMLLIElement.ariaActiveDescendantElement": null,
  "HTMLLIElement.ariaControlsElements": null,
  "HTMLLIElement.ariaDescribedByElements": null,
  "HTMLLIElement.ariaDetailsElements": null,
  "HTMLLIElement.ariaErrorMessageElements": null,
  "HTMLLIElement.ariaFlowToElements": null,
  "HTMLLIElement.ariaLabelledByElements": null,
  "HTMLLIElement.ariaOwnsElements": null,
  "HTMLLIElement.firstElementChild": null,
  "HTMLLIElement.lastElementChild": null,
  "HTMLLIElement.previousElementSibling": null,
  "HTMLLIElement.nextElementSibling": null,
  "HTMLLIElement.scrollParent": null,
  "HTMLLIElement.offsetParent": null,
  "HTMLLoginElement.ownerDocument": null,
  "HTMLLoginElement.parentNode": null,
  "HTMLLoginElement.parentElement": null,
  "HTMLLoginElement.childNodes": null,
  "HTMLLoginElement.firstChild": null,
  "HTMLLoginElement.lastChild": null,
  "HTMLLoginElement.previousSibling": null,
  "HTMLLoginElement.nextSibling": null,
  "HTMLLoginElement.attributes": null,
  "HTMLLoginElement.shadowRoot": null,
  "HTMLLoginElement.assignedSlot": "slot",
  "HTMLLoginElement.customElementRegistry": null,
  "HTMLLoginElement.ariaActiveDescendantElement": null,
  "HTMLLoginElement.ariaControlsElements": null,
  "HTMLLoginElement.ariaDescribedByElements": null,
  "HTMLLoginElement.ariaDetailsElements": null,
  "HTMLLoginElement.ariaErrorMessageElements": null,
  "HTMLLoginElement.ariaFlowToElements": null,
  "HTMLLoginElement.ariaLabelledByElements": null,
  "HTMLLoginElement.ariaOwnsElements": null,
  "HTMLLoginElement.firstElementChild": null,
  "HTMLLoginElement.lastElementChild": null,
  "HTMLLoginElement.previousElementSibling": null,
  "HTMLLoginElement.nextElementSibling": null,
  "HTMLLoginElement.scrollParent": null,
  "HTMLLoginElement.offsetParent": null,
  "HTMLMapElement.ownerDocument": null,
  "HTMLMapElement.parentNode": null,
  "HTMLMapElement.parentElement": null,
  "HTMLMapElement.childNodes": null,
  "HTMLMapElement.firstChild": null,
  "HTMLMapElement.lastChild": null,
  "HTMLMapElement.previousSibling": null,
  "HTMLMapElement.nextSibling": null,
  "HTMLMapElement.attributes": null,
  "HTMLMapElement.shadowRoot": null,
  "HTMLMapElement.assignedSlot": "slot",
  "HTMLMapElement.customElementRegistry": null,
  "HTMLMapElement.ariaActiveDescendantElement": null,
  "HTMLMapElement.ariaControlsElements": null,
  "HTMLMapElement.ariaDescribedByElements": null,
  "HTMLMapElement.ariaDetailsElements": null,
  "HTMLMapElement.ariaErrorMessageElements": null,
  "HTMLMapElement.ariaFlowToElements": null,
  "HTMLMapElement.ariaLabelledByElements": null,
  "HTMLMapElement.ariaOwnsElements": null,
  "HTMLMapElement.firstElementChild": null,
  "HTMLMapElement.lastElementChild": null,
  "HTMLMapElement.previousElementSibling": null,
  "HTMLMapElement.nextElementSibling": null,
  "HTMLMapElement.scrollParent": null,
  "HTMLMapElement.offsetParent": null,
  "HTMLMarqueeElement.ownerDocument": null,
  "HTMLMarqueeElement.parentNode": null,
  "HTMLMarqueeElement.parentElement": null,
  "HTMLMarqueeElement.childNodes": null,
  "HTMLMarqueeElement.firstChild": null,
  "HTMLMarqueeElement.lastChild": null,
  "HTMLMarqueeElement.previousSibling": null,
  "HTMLMarqueeElement.nextSibling": null,
  "HTMLMarqueeElement.attributes": null,
  "HTMLMarqueeElement.shadowRoot": null,
  "HTMLMarqueeElement.assignedSlot": "slot",
  "HTMLMarqueeElement.customElementRegistry": null,
  "HTMLMarqueeElement.ariaActiveDescendantElement": null,
  "HTMLMarqueeElement.ariaControlsElements": null,
  "HTMLMarqueeElement.ariaDescribedByElements": null,
  "HTMLMarqueeElement.ariaDetailsElements": null,
  "HTMLMarqueeElement.ariaErrorMessageElements": null,
  "HTMLMarqueeElement.ariaFlowToElements": null,
  "HTMLMarqueeElement.ariaLabelledByElements": null,
  "HTMLMarqueeElement.ariaOwnsElements": null,
  "HTMLMarqueeElement.firstElementChild": null,
  "HTMLMarqueeElement.lastElementChild": null,
  "HTMLMarqueeElement.previousElementSibling": null,
  "HTMLMarqueeElement.nextElementSibling": null,
  "HTMLMarqueeElement.scrollParent": null,
  "HTMLMarqueeElement.offsetParent": null,
  "HTMLMenuBarElement.ownerDocument": null,
  "HTMLMenuBarElement.parentNode": null,
  "HTMLMenuBarElement.parentElement": null,
  "HTMLMenuBarElement.childNodes": null,
  "HTMLMenuBarElement.firstChild": null,
  "HTMLMenuBarElement.lastChild": null,
  "HTMLMenuBarElement.previousSibling": null,
  "HTMLMenuBarElement.nextSibling": null,
  "HTMLMenuBarElement.attributes": null,
  "HTMLMenuBarElement.shadowRoot": null,
  "HTMLMenuBarElement.assignedSlot": "slot",
  "HTMLMenuBarElement.customElementRegistry": null,
  "HTMLMenuBarElement.ariaActiveDescendantElement": null,
  "HTMLMenuBarElement.ariaControlsElements": null,
  "HTMLMenuBarElement.ariaDescribedByElements": null,
  "HTMLMenuBarElement.ariaDetailsElements": null,
  "HTMLMenuBarElement.ariaErrorMessageElements": null,
  "HTMLMenuBarElement.ariaFlowToElements": null,
  "HTMLMenuBarElement.ariaLabelledByElements": null,
  "HTMLMenuBarElement.ariaOwnsElements": null,
  "HTMLMenuBarElement.firstElementChild": null,
  "HTMLMenuBarElement.lastElementChild": null,
  "HTMLMenuBarElement.previousElementSibling": null,
  "HTMLMenuBarElement.nextElementSibling": null,
  "HTMLMenuBarElement.scrollParent": null,
  "HTMLMenuBarElement.offsetParent": null,
  "HTMLMenuElement.ownerDocument": null,
  "HTMLMenuElement.parentNode": null,
  "HTMLMenuElement.parentElement": null,
  "HTMLMenuElement.childNodes": null,
  "HTMLMenuElement.firstChild": null,
  "HTMLMenuElement.lastChild": null,
  "HTMLMenuElement.previousSibling": null,
  "HTMLMenuElement.nextSibling": null,
  "HTMLMenuElement.attributes": null,
  "HTMLMenuElement.shadowRoot": null,
  "HTMLMenuElement.assignedSlot": "slot",
  "HTMLMenuElement.customElementRegistry": null,
  "HTMLMenuElement.ariaActiveDescendantElement": null,
  "HTMLMenuElement.ariaControlsElements": null,
  "HTMLMenuElement.ariaDescribedByElements": null,
  "HTMLMenuElement.ariaDetailsElements": null,
  "HTMLMenuElement.ariaErrorMessageElements": null,
  "HTMLMenuElement.ariaFlowToElements": null,
  "HTMLMenuElement.ariaLabelledByElements": null,
  "HTMLMenuElement.ariaOwnsElements": null,
  "HTMLMenuElement.firstElementChild": null,
  "HTMLMenuElement.lastElementChild": null,
  "HTMLMenuElement.previousElementSibling": null,
  "HTMLMenuElement.nextElementSibling": null,
  "HTMLMenuElement.scrollParent": null,
  "HTMLMenuElement.offsetParent": null,
  "HTMLMenuItemElement.ownerDocument": null,
  "HTMLMenuItemElement.parentNode": null,
  "HTMLMenuItemElement.parentElement": null,
  "HTMLMenuItemElement.childNodes": null,
  "HTMLMenuItemElement.firstChild": null,
  "HTMLMenuItemElement.lastChild": null,
  "HTMLMenuItemElement.previousSibling": null,
  "HTMLMenuItemElement.nextSibling": null,
  "HTMLMenuItemElement.attributes": null,
  "HTMLMenuItemElement.shadowRoot": null,
  "HTMLMenuItemElement.assignedSlot": "slot",
  "HTMLMenuItemElement.customElementRegistry": null,
  "HTMLMenuItemElement.ariaActiveDescendantElement": null,
  "HTMLMenuItemElement.ariaControlsElements": null,
  "HTMLMenuItemElement.ariaDescribedByElements": null,
  "HTMLMenuItemElement.ariaDetailsElements": null,
  "HTMLMenuItemElement.ariaErrorMessageElements": null,
  "HTMLMenuItemElement.ariaFlowToElements": null,
  "HTMLMenuItemElement.ariaLabelledByElements": null,
  "HTMLMenuItemElement.ariaOwnsElements": null,
  "HTMLMenuItemElement.firstElementChild": null,
  "HTMLMenuItemElement.lastElementChild": null,
  "HTMLMenuItemElement.previousElementSibling": null,
  "HTMLMenuItemElement.nextElementSibling": null,
  "HTMLMenuItemElement.scrollParent": null,
  "HTMLMenuItemElement.offsetParent": null,
  "HTMLMenuItemElement.commandForElement": null,
  "HTMLMenuItemElement.interestForElement": null,
  "HTMLMenuListElement.ownerDocument": null,
  "HTMLMenuListElement.parentNode": null,
  "HTMLMenuListElement.parentElement": null,
  "HTMLMenuListElement.childNodes": null,
  "HTMLMenuListElement.firstChild": null,
  "HTMLMenuListElement.lastChild": null,
  "HTMLMenuListElement.previousSibling": null,
  "HTMLMenuListElement.nextSibling": null,
  "HTMLMenuListElement.attributes": null,
  "HTMLMenuListElement.shadowRoot": null,
  "HTMLMenuListElement.assignedSlot": "slot",
  "HTMLMenuListElement.customElementRegistry": null,
  "HTMLMenuListElement.ariaActiveDescendantElement": null,
  "HTMLMenuListElement.ariaControlsElements": null,
  "HTMLMenuListElement.ariaDescribedByElements": null,
  "HTMLMenuListElement.ariaDetailsElements": null,
  "HTMLMenuListElement.ariaErrorMessageElements": null,
  "HTMLMenuListElement.ariaFlowToElements": null,
  "HTMLMenuListElement.ariaLabelledByElements": null,
  "HTMLMenuListElement.ariaOwnsElements": null,
  "HTMLMenuListElement.firstElementChild": null,
  "HTMLMenuListElement.lastElementChild": null,
  "HTMLMenuListElement.previousElementSibling": null,
  "HTMLMenuListElement.nextElementSibling": null,
  "HTMLMenuListElement.scrollParent": null,
  "HTMLMenuListElement.offsetParent": null,
  "HTMLMetaElement.ownerDocument": null,
  "HTMLMetaElement.parentNode": null,
  "HTMLMetaElement.parentElement": null,
  "HTMLMetaElement.childNodes": null,
  "HTMLMetaElement.firstChild": null,
  "HTMLMetaElement.lastChild": null,
  "HTMLMetaElement.previousSibling": null,
  "HTMLMetaElement.nextSibling": null,
  "HTMLMetaElement.attributes": null,
  "HTMLMetaElement.shadowRoot": null,
  "HTMLMetaElement.assignedSlot": "slot",
  "HTMLMetaElement.customElementRegistry": null,
  "HTMLMetaElement.ariaActiveDescendantElement": null,
  "HTMLMetaElement.ariaControlsElements": null,
  "HTMLMetaElement.ariaDescribedByElements": null,
  "HTMLMetaElement.ariaDetailsElements": null,
  "HTMLMetaElement.ariaErrorMessageElements": null,
  "HTMLMetaElement.ariaFlowToElements": null,
  "HTMLMetaElement.ariaLabelledByElements": null,
  "HTMLMetaElement.ariaOwnsElements": null,
  "HTMLMetaElement.firstElementChild": null,
  "HTMLMetaElement.lastElementChild": null,
  "HTMLMetaElement.previousElementSibling": null,
  "HTMLMetaElement.nextElementSibling": null,
  "HTMLMetaElement.scrollParent": null,
  "HTMLMetaElement.offsetParent": null,
  "HTMLMeterElement.ownerDocument": null,
  "HTMLMeterElement.parentNode": null,
  "HTMLMeterElement.parentElement": null,
  "HTMLMeterElement.childNodes": null,
  "HTMLMeterElement.firstChild": null,
  "HTMLMeterElement.lastChild": null,
  "HTMLMeterElement.previousSibling": null,
  "HTMLMeterElement.nextSibling": null,
  "HTMLMeterElement.attributes": null,
  "HTMLMeterElement.shadowRoot": null,
  "HTMLMeterElement.assignedSlot": "slot",
  "HTMLMeterElement.customElementRegistry": null,
  "HTMLMeterElement.ariaActiveDescendantElement": null,
  "HTMLMeterElement.ariaControlsElements": null,
  "HTMLMeterElement.ariaDescribedByElements": null,
  "HTMLMeterElement.ariaDetailsElements": null,
  "HTMLMeterElement.ariaErrorMessageElements": null,
  "HTMLMeterElement.ariaFlowToElements": null,
  "HTMLMeterElement.ariaLabelledByElements": null,
  "HTMLMeterElement.ariaOwnsElements": null,
  "HTMLMeterElement.firstElementChild": null,
  "HTMLMeterElement.lastElementChild": null,
  "HTMLMeterElement.previousElementSibling": null,
  "HTMLMeterElement.nextElementSibling": null,
  "HTMLMeterElement.scrollParent": null,
  "HTMLMeterElement.offsetParent": null,
  "HTMLMeterElement.labels": null,
  "HTMLModElement.ownerDocument": null,
  "HTMLModElement.parentNode": null,
  "HTMLModElement.parentElement": null,
  "HTMLModElement.childNodes": null,
  "HTMLModElement.firstChild": null,
  "HTMLModElement.lastChild": null,
  "HTMLModElement.previousSibling": null,
  "HTMLModElement.nextSibling": null,
  "HTMLModElement.attributes": null,
  "HTMLModElement.shadowRoot": null,
  "HTMLModElement.assignedSlot": "slot",
  "HTMLModElement.customElementRegistry": null,
  "HTMLModElement.ariaActiveDescendantElement": null,
  "HTMLModElement.ariaControlsElements": null,
  "HTMLModElement.ariaDescribedByElements": null,
  "HTMLModElement.ariaDetailsElements": null,
  "HTMLModElement.ariaErrorMessageElements": null,
  "HTMLModElement.ariaFlowToElements": null,
  "HTMLModElement.ariaLabelledByElements": null,
  "HTMLModElement.ariaOwnsElements": null,
  "HTMLModElement.firstElementChild": null,
  "HTMLModElement.lastElementChild": null,
  "HTMLModElement.previousElementSibling": null,
  "HTMLModElement.nextElementSibling": null,
  "HTMLModElement.scrollParent": null,
  "HTMLModElement.offsetParent": null,
  "HTMLObjectElement.ownerDocument": null,
  "HTMLObjectElement.parentNode": null,
  "HTMLObjectElement.parentElement": null,
  "HTMLObjectElement.childNodes": null,
  "HTMLObjectElement.firstChild": null,
  "HTMLObjectElement.lastChild": null,
  "HTMLObjectElement.previousSibling": null,
  "HTMLObjectElement.nextSibling": null,
  "HTMLObjectElement.attributes": null,
  "HTMLObjectElement.shadowRoot": null,
  "HTMLObjectElement.assignedSlot": "slot",
  "HTMLObjectElement.customElementRegistry": null,
  "HTMLObjectElement.ariaActiveDescendantElement": null,
  "HTMLObjectElement.ariaControlsElements": null,
  "HTMLObjectElement.ariaDescribedByElements": null,
  "HTMLObjectElement.ariaDetailsElements": null,
  "HTMLObjectElement.ariaErrorMessageElements": null,
  "HTMLObjectElement.ariaFlowToElements": null,
  "HTMLObjectElement.ariaLabelledByElements": null,
  "HTMLObjectElement.ariaOwnsElements": null,
  "HTMLObjectElement.firstElementChild": null,
  "HTMLObjectElement.lastElementChild": null,
  "HTMLObjectElement.previousElementSibling": null,
  "HTMLObjectElement.nextElementSibling": null,
  "HTMLObjectElement.scrollParent": null,
  "HTMLObjectElement.offsetParent": null,
  "HTMLObjectElement.form": null,
  "HTMLObjectElement.contentDocument": null,
  "HTMLOListElement.ownerDocument": null,
  "HTMLOListElement.parentNode": null,
  "HTMLOListElement.parentElement": null,
  "HTMLOListElement.childNodes": null,
  "HTMLOListElement.firstChild": null,
  "HTMLOListElement.lastChild": null,
  "HTMLOListElement.previousSibling": null,
  "HTMLOListElement.nextSibling": null,
  "HTMLOListElement.attributes": null,
  "HTMLOListElement.shadowRoot": null,
  "HTMLOListElement.assignedSlot": "slot",
  "HTMLOListElement.customElementRegistry": null,
  "HTMLOListElement.ariaActiveDescendantElement": null,
  "HTMLOListElement.ariaControlsElements": null,
  "HTMLOListElement.ariaDescribedByElements": null,
  "HTMLOListElement.ariaDetailsElements": null,
  "HTMLOListElement.ariaErrorMessageElements": null,
  "HTMLOListElement.ariaFlowToElements": null,
  "HTMLOListElement.ariaLabelledByElements": null,
  "HTMLOListElement.ariaOwnsElements": null,
  "HTMLOListElement.firstElementChild": null,
  "HTMLOListElement.lastElementChild": null,
  "HTMLOListElement.previousElementSibling": null,
  "HTMLOListElement.nextElementSibling": null,
  "HTMLOListElement.scrollParent": null,
  "HTMLOListElement.offsetParent": null,
  "HTMLParagraphElement.ownerDocument": null,
  "HTMLParagraphElement.parentNode": null,
  "HTMLParagraphElement.parentElement": null,
  "HTMLParagraphElement.childNodes": null,
  "HTMLParagraphElement.firstChild": null,
  "HTMLParagraphElement.lastChild": null,
  "HTMLParagraphElement.previousSibling": null,
  "HTMLParagraphElement.nextSibling": null,
  "HTMLParagraphElement.attributes": null,
  "HTMLParagraphElement.shadowRoot": null,
  "HTMLParagraphElement.assignedSlot": "slot",
  "HTMLParagraphElement.customElementRegistry": null,
  "HTMLParagraphElement.ariaActiveDescendantElement": null,
  "HTMLParagraphElement.ariaControlsElements": null,
  "HTMLParagraphElement.ariaDescribedByElements": null,
  "HTMLParagraphElement.ariaDetailsElements": null,
  "HTMLParagraphElement.ariaErrorMessageElements": null,
  "HTMLParagraphElement.ariaFlowToElements": null,
  "HTMLParagraphElement.ariaLabelledByElements": null,
  "HTMLParagraphElement.ariaOwnsElements": null,
  "HTMLParagraphElement.firstElementChild": null,
  "HTMLParagraphElement.lastElementChild": null,
  "HTMLParagraphElement.previousElementSibling": null,
  "HTMLParagraphElement.nextElementSibling": null,
  "HTMLParagraphElement.scrollParent": null,
  "HTMLParagraphElement.offsetParent": null,
  "HTMLParamElement.ownerDocument": null,
  "HTMLParamElement.parentNode": null,
  "HTMLParamElement.parentElement": null,
  "HTMLParamElement.childNodes": null,
  "HTMLParamElement.firstChild": null,
  "HTMLParamElement.lastChild": null,
  "HTMLParamElement.previousSibling": null,
  "HTMLParamElement.nextSibling": null,
  "HTMLParamElement.attributes": null,
  "HTMLParamElement.shadowRoot": null,
  "HTMLParamElement.assignedSlot": "slot",
  "HTMLParamElement.customElementRegistry": null,
  "HTMLParamElement.ariaActiveDescendantElement": null,
  "HTMLParamElement.ariaControlsElements": null,
  "HTMLParamElement.ariaDescribedByElements": null,
  "HTMLParamElement.ariaDetailsElements": null,
  "HTMLParamElement.ariaErrorMessageElements": null,
  "HTMLParamElement.ariaFlowToElements": null,
  "HTMLParamElement.ariaLabelledByElements": null,
  "HTMLParamElement.ariaOwnsElements": null,
  "HTMLParamElement.firstElementChild": null,
  "HTMLParamElement.lastElementChild": null,
  "HTMLParamElement.previousElementSibling": null,
  "HTMLParamElement.nextElementSibling": null,
  "HTMLParamElement.scrollParent": null,
  "HTMLParamElement.offsetParent": null,
  "HTMLPictureElement.ownerDocument": null,
  "HTMLPictureElement.parentNode": null,
  "HTMLPictureElement.parentElement": null,
  "HTMLPictureElement.childNodes": null,
  "HTMLPictureElement.firstChild": null,
  "HTMLPictureElement.lastChild": null,
  "HTMLPictureElement.previousSibling": null,
  "HTMLPictureElement.nextSibling": null,
  "HTMLPictureElement.attributes": null,
  "HTMLPictureElement.shadowRoot": null,
  "HTMLPictureElement.assignedSlot": "slot",
  "HTMLPictureElement.customElementRegistry": null,
  "HTMLPictureElement.ariaActiveDescendantElement": null,
  "HTMLPictureElement.ariaControlsElements": null,
  "HTMLPictureElement.ariaDescribedByElements": null,
  "HTMLPictureElement.ariaDetailsElements": null,
  "HTMLPictureElement.ariaErrorMessageElements": null,
  "HTMLPictureElement.ariaFlowToElements": null,
  "HTMLPictureElement.ariaLabelledByElements": null,
  "HTMLPictureElement.ariaOwnsElements": null,
  "HTMLPictureElement.firstElementChild": null,
  "HTMLPictureElement.lastElementChild": null,
  "HTMLPictureElement.previousElementSibling": null,
  "HTMLPictureElement.nextElementSibling": null,
  "HTMLPictureElement.scrollParent": null,
  "HTMLPictureElement.offsetParent": null,
  "HTMLPreElement.ownerDocument": null,
  "HTMLPreElement.parentNode": null,
  "HTMLPreElement.parentElement": null,
  "HTMLPreElement.childNodes": null,
  "HTMLPreElement.firstChild": null,
  "HTMLPreElement.lastChild": null,
  "HTMLPreElement.previousSibling": null,
  "HTMLPreElement.nextSibling": null,
  "HTMLPreElement.attributes": null,
  "HTMLPreElement.shadowRoot": null,
  "HTMLPreElement.assignedSlot": "slot",
  "HTMLPreElement.customElementRegistry": null,
  "HTMLPreElement.ariaActiveDescendantElement": null,
  "HTMLPreElement.ariaControlsElements": null,
  "HTMLPreElement.ariaDescribedByElements": null,
  "HTMLPreElement.ariaDetailsElements": null,
  "HTMLPreElement.ariaErrorMessageElements": null,
  "HTMLPreElement.ariaFlowToElements": null,
  "HTMLPreElement.ariaLabelledByElements": null,
  "HTMLPreElement.ariaOwnsElements": null,
  "HTMLPreElement.firstElementChild": null,
  "HTMLPreElement.lastElementChild": null,
  "HTMLPreElement.previousElementSibling": null,
  "HTMLPreElement.nextElementSibling": null,
  "HTMLPreElement.scrollParent": null,
  "HTMLPreElement.offsetParent": null,
  "HTMLProgressElement.ownerDocument": null,
  "HTMLProgressElement.parentNode": null,
  "HTMLProgressElement.parentElement": null,
  "HTMLProgressElement.childNodes": null,
  "HTMLProgressElement.firstChild": null,
  "HTMLProgressElement.lastChild": null,
  "HTMLProgressElement.previousSibling": null,
  "HTMLProgressElement.nextSibling": null,
  "HTMLProgressElement.attributes": null,
  "HTMLProgressElement.shadowRoot": null,
  "HTMLProgressElement.assignedSlot": "slot",
  "HTMLProgressElement.customElementRegistry": null,
  "HTMLProgressElement.ariaActiveDescendantElement": null,
  "HTMLProgressElement.ariaControlsElements": null,
  "HTMLProgressElement.ariaDescribedByElements": null,
  "HTMLProgressElement.ariaDetailsElements": null,
  "HTMLProgressElement.ariaErrorMessageElements": null,
  "HTMLProgressElement.ariaFlowToElements": null,
  "HTMLProgressElement.ariaLabelledByElements": null,
  "HTMLProgressElement.ariaOwnsElements": null,
  "HTMLProgressElement.firstElementChild": null,
  "HTMLProgressElement.lastElementChild": null,
  "HTMLProgressElement.previousElementSibling": null,
  "HTMLProgressElement.nextElementSibling": null,
  "HTMLProgressElement.scrollParent": null,
  "HTMLProgressElement.offsetParent": null,
  "HTMLProgressElement.labels": null,
  "HTMLQuoteElement.ownerDocument": null,
  "HTMLQuoteElement.parentNode": null,
  "HTMLQuoteElement.parentElement": null,
  "HTMLQuoteElement.childNodes": null,
  "HTMLQuoteElement.firstChild": null,
  "HTMLQuoteElement.lastChild": null,
  "HTMLQuoteElement.previousSibling": null,
  "HTMLQuoteElement.nextSibling": null,
  "HTMLQuoteElement.attributes": null,
  "HTMLQuoteElement.shadowRoot": null,
  "HTMLQuoteElement.assignedSlot": "slot",
  "HTMLQuoteElement.customElementRegistry": null,
  "HTMLQuoteElement.ariaActiveDescendantElement": null,
  "HTMLQuoteElement.ariaControlsElements": null,
  "HTMLQuoteElement.ariaDescribedByElements": null,
  "HTMLQuoteElement.ariaDetailsElements": null,
  "HTMLQuoteElement.ariaErrorMessageElements": null,
  "HTMLQuoteElement.ariaFlowToElements": null,
  "HTMLQuoteElement.ariaLabelledByElements": null,
  "HTMLQuoteElement.ariaOwnsElements": null,
  "HTMLQuoteElement.firstElementChild": null,
  "HTMLQuoteElement.lastElementChild": null,
  "HTMLQuoteElement.previousElementSibling": null,
  "HTMLQuoteElement.nextElementSibling": null,
  "HTMLQuoteElement.scrollParent": null,
  "HTMLQuoteElement.offsetParent": null,
  "HTMLScriptElement.ownerDocument": null,
  "HTMLScriptElement.parentNode": null,
  "HTMLScriptElement.parentElement": null,
  "HTMLScriptElement.childNodes": null,
  "HTMLScriptElement.firstChild": null,
  "HTMLScriptElement.lastChild": null,
  "HTMLScriptElement.previousSibling": null,
  "HTMLScriptElement.nextSibling": null,
  "HTMLScriptElement.attributes": null,
  "HTMLScriptElement.shadowRoot": null,
  "HTMLScriptElement.assignedSlot": "slot",
  "HTMLScriptElement.customElementRegistry": null,
  "HTMLScriptElement.ariaActiveDescendantElement": null,
  "HTMLScriptElement.ariaControlsElements": null,
  "HTMLScriptElement.ariaDescribedByElements": null,
  "HTMLScriptElement.ariaDetailsElements": null,
  "HTMLScriptElement.ariaErrorMessageElements": null,
  "HTMLScriptElement.ariaFlowToElements": null,
  "HTMLScriptElement.ariaLabelledByElements": null,
  "HTMLScriptElement.ariaOwnsElements": null,
  "HTMLScriptElement.firstElementChild": null,
  "HTMLScriptElement.lastElementChild": null,
  "HTMLScriptElement.previousElementSibling": null,
  "HTMLScriptElement.nextElementSibling": null,
  "HTMLScriptElement.scrollParent": null,
  "HTMLScriptElement.offsetParent": null,
  "HTMLSlotElement.ownerDocument": null,
  "HTMLSlotElement.parentNode": null,
  "HTMLSlotElement.parentElement": null,
  "HTMLSlotElement.childNodes": null,
  "HTMLSlotElement.firstChild": null,
  "HTMLSlotElement.lastChild": null,
  "HTMLSlotElement.previousSibling": null,
  "HTMLSlotElement.nextSibling": null,
  "HTMLSlotElement.attributes": null,
  "HTMLSlotElement.shadowRoot": null,
  "HTMLSlotElement.assignedSlot": "slot",
  "HTMLSlotElement.customElementRegistry": null,
  "HTMLSlotElement.ariaActiveDescendantElement": null,
  "HTMLSlotElement.ariaControlsElements": null,
  "HTMLSlotElement.ariaDescribedByElements": null,
  "HTMLSlotElement.ariaDetailsElements": null,
  "HTMLSlotElement.ariaErrorMessageElements": null,
  "HTMLSlotElement.ariaFlowToElements": null,
  "HTMLSlotElement.ariaLabelledByElements": null,
  "HTMLSlotElement.ariaOwnsElements": null,
  "HTMLSlotElement.firstElementChild": null,
  "HTMLSlotElement.lastElementChild": null,
  "HTMLSlotElement.previousElementSibling": null,
  "HTMLSlotElement.nextElementSibling": null,
  "HTMLSlotElement.scrollParent": null,
  "HTMLSlotElement.offsetParent": null,
  "HTMLSourceElement.ownerDocument": null,
  "HTMLSourceElement.parentNode": null,
  "HTMLSourceElement.parentElement": null,
  "HTMLSourceElement.childNodes": null,
  "HTMLSourceElement.firstChild": null,
  "HTMLSourceElement.lastChild": null,
  "HTMLSourceElement.previousSibling": null,
  "HTMLSourceElement.nextSibling": null,
  "HTMLSourceElement.attributes": null,
  "HTMLSourceElement.shadowRoot": null,
  "HTMLSourceElement.assignedSlot": "slot",
  "HTMLSourceElement.customElementRegistry": null,
  "HTMLSourceElement.ariaActiveDescendantElement": null,
  "HTMLSourceElement.ariaControlsElements": null,
  "HTMLSourceElement.ariaDescribedByElements": null,
  "HTMLSourceElement.ariaDetailsElements": null,
  "HTMLSourceElement.ariaErrorMessageElements": null,
  "HTMLSourceElement.ariaFlowToElements": null,
  "HTMLSourceElement.ariaLabelledByElements": null,
  "HTMLSourceElement.ariaOwnsElements": null,
  "HTMLSourceElement.firstElementChild": null,
  "HTMLSourceElement.lastElementChild": null,
  "HTMLSourceElement.previousElementSibling": null,
  "HTMLSourceElement.nextElementSibling": null,
  "HTMLSourceElement.scrollParent": null,
  "HTMLSourceElement.offsetParent": null,
  "HTMLSpanElement.ownerDocument": null,
  "HTMLSpanElement.parentNode": null,
  "HTMLSpanElement.parentElement": null,
  "HTMLSpanElement.childNodes": null,
  "HTMLSpanElement.firstChild": null,
  "HTMLSpanElement.lastChild": null,
  "HTMLSpanElement.previousSibling": null,
  "HTMLSpanElement.nextSibling": null,
  "HTMLSpanElement.attributes": null,
  "HTMLSpanElement.shadowRoot": null,
  "HTMLSpanElement.assignedSlot": "slot",
  "HTMLSpanElement.customElementRegistry": null,
  "HTMLSpanElement.ariaActiveDescendantElement": null,
  "HTMLSpanElement.ariaControlsElements": null,
  "HTMLSpanElement.ariaDescribedByElements": null,
  "HTMLSpanElement.ariaDetailsElements": null,
  "HTMLSpanElement.ariaErrorMessageElements": null,
  "HTMLSpanElement.ariaFlowToElements": null,
  "HTMLSpanElement.ariaLabelledByElements": null,
  "HTMLSpanElement.ariaOwnsElements": null,
  "HTMLSpanElement.firstElementChild": null,
  "HTMLSpanElement.lastElementChild": null,
  "HTMLSpanElement.previousElementSibling": null,
  "HTMLSpanElement.nextElementSibling": null,
  "HTMLSpanElement.scrollParent": null,
  "HTMLSpanElement.offsetParent": null,
  "HTMLStyleElement.ownerDocument": null,
  "HTMLStyleElement.parentNode": null,
  "HTMLStyleElement.parentElement": null,
  "HTMLStyleElement.childNodes": null,
  "HTMLStyleElement.firstChild": null,
  "HTMLStyleElement.lastChild": null,
  "HTMLStyleElement.previousSibling": null,
  "HTMLStyleElement.nextSibling": null,
  "HTMLStyleElement.attributes": null,
  "HTMLStyleElement.shadowRoot": null,
  "HTMLStyleElement.assignedSlot": "slot",
  "HTMLStyleElement.customElementRegistry": null,
  "HTMLStyleElement.ariaActiveDescendantElement": null,
  "HTMLStyleElement.ariaControlsElements": null,
  "HTMLStyleElement.ariaDescribedByElements": null,
  "HTMLStyleElement.ariaDetailsElements": null,
  "HTMLStyleElement.ariaErrorMessageElements": null,
  "HTMLStyleElement.ariaFlowToElements": null,
  "HTMLStyleElement.ariaLabelledByElements": null,
  "HTMLStyleElement.ariaOwnsElements": null,
  "HTMLStyleElement.firstElementChild": null,
  "HTMLStyleElement.lastElementChild": null,
  "HTMLStyleElement.previousElementSibling": null,
  "HTMLStyleElement.nextElementSibling": null,
  "HTMLStyleElement.scrollParent": null,
  "HTMLStyleElement.offsetParent": null,
  "HTMLTableCaptionElement.ownerDocument": null,
  "HTMLTableCaptionElement.parentNode": null,
  "HTMLTableCaptionElement.parentElement": null,
  "HTMLTableCaptionElement.childNodes": null,
  "HTMLTableCaptionElement.firstChild": null,
  "HTMLTableCaptionElement.lastChild": null,
  "HTMLTableCaptionElement.previousSibling": null,
  "HTMLTableCaptionElement.nextSibling": null,
  "HTMLTableCaptionElement.attributes": null,
  "HTMLTableCaptionElement.shadowRoot": null,
  "HTMLTableCaptionElement.assignedSlot": "slot",
  "HTMLTableCaptionElement.customElementRegistry": null,
  "HTMLTableCaptionElement.ariaActiveDescendantElement": null,
  "HTMLTableCaptionElement.ariaControlsElements": null,
  "HTMLTableCaptionElement.ariaDescribedByElements": null,
  "HTMLTableCaptionElement.ariaDetailsElements": null,
  "HTMLTableCaptionElement.ariaErrorMessageElements": null,
  "HTMLTableCaptionElement.ariaFlowToElements": null,
  "HTMLTableCaptionElement.ariaLabelledByElements": null,
  "HTMLTableCaptionElement.ariaOwnsElements": null,
  "HTMLTableCaptionElement.firstElementChild": null,
  "HTMLTableCaptionElement.lastElementChild": null,
  "HTMLTableCaptionElement.previousElementSibling": null,
  "HTMLTableCaptionElement.nextElementSibling": null,
  "HTMLTableCaptionElement.scrollParent": null,
  "HTMLTableCaptionElement.offsetParent": null,
  "HTMLTableCellElement.ownerDocument": null,
  "HTMLTableCellElement.parentNode": null,
  "HTMLTableCellElement.parentElement": null,
  "HTMLTableCellElement.childNodes": null,
  "HTMLTableCellElement.firstChild": null,
  "HTMLTableCellElement.lastChild": null,
  "HTMLTableCellElement.previousSibling": null,
  "HTMLTableCellElement.nextSibling": null,
  "HTMLTableCellElement.attributes": null,
  "HTMLTableCellElement.shadowRoot": null,
  "HTMLTableCellElement.assignedSlot": "slot",
  "HTMLTableCellElement.customElementRegistry": null,
  "HTMLTableCellElement.ariaActiveDescendantElement": null,
  "HTMLTableCellElement.ariaControlsElements": null,
  "HTMLTableCellElement.ariaDescribedByElements": null,
  "HTMLTableCellElement.ariaDetailsElements": null,
  "HTMLTableCellElement.ariaErrorMessageElements": null,
  "HTMLTableCellElement.ariaFlowToElements": null,
  "HTMLTableCellElement.ariaLabelledByElements": null,
  "HTMLTableCellElement.ariaOwnsElements": null,
  "HTMLTableCellElement.firstElementChild": null,
  "HTMLTableCellElement.lastElementChild": null,
  "HTMLTableCellElement.previousElementSibling": null,
  "HTMLTableCellElement.nextElementSibling": null,
  "HTMLTableCellElement.scrollParent": null,
  "HTMLTableCellElement.offsetParent": null,
  "HTMLTableColElement.ownerDocument": null,
  "HTMLTableColElement.parentNode": null,
  "HTMLTableColElement.parentElement": null,
  "HTMLTableColElement.childNodes": null,
  "HTMLTableColElement.firstChild": null,
  "HTMLTableColElement.lastChild": null,
  "HTMLTableColElement.previousSibling": null,
  "HTMLTableColElement.nextSibling": null,
  "HTMLTableColElement.attributes": null,
  "HTMLTableColElement.shadowRoot": null,
  "HTMLTableColElement.assignedSlot": "slot",
  "HTMLTableColElement.customElementRegistry": null,
  "HTMLTableColElement.ariaActiveDescendantElement": null,
  "HTMLTableColElement.ariaControlsElements": null,
  "HTMLTableColElement.ariaDescribedByElements": null,
  "HTMLTableColElement.ariaDetailsElements": null,
  "HTMLTableColElement.ariaErrorMessageElements": null,
  "HTMLTableColElement.ariaFlowToElements": null,
  "HTMLTableColElement.ariaLabelledByElements": null,
  "HTMLTableColElement.ariaOwnsElements": null,
  "HTMLTableColElement.firstElementChild": null,
  "HTMLTableColElement.lastElementChild": null,
  "HTMLTableColElement.previousElementSibling": null,
  "HTMLTableColElement.nextElementSibling": null,
  "HTMLTableColElement.scrollParent": null,
  "HTMLTableColElement.offsetParent": null,
  "HTMLTableElement.ownerDocument": null,
  "HTMLTableElement.parentNode": null,
  "HTMLTableElement.parentElement": null,
  "HTMLTableElement.childNodes": null,
  "HTMLTableElement.firstChild": null,
  "HTMLTableElement.lastChild": null,
  "HTMLTableElement.previousSibling": null,
  "HTMLTableElement.nextSibling": null,
  "HTMLTableElement.attributes": null,
  "HTMLTableElement.shadowRoot": null,
  "HTMLTableElement.assignedSlot": "slot",
  "HTMLTableElement.customElementRegistry": null,
  "HTMLTableElement.ariaActiveDescendantElement": null,
  "HTMLTableElement.ariaControlsElements": null,
  "HTMLTableElement.ariaDescribedByElements": null,
  "HTMLTableElement.ariaDetailsElements": null,
  "HTMLTableElement.ariaErrorMessageElements": null,
  "HTMLTableElement.ariaFlowToElements": null,
  "HTMLTableElement.ariaLabelledByElements": null,
  "HTMLTableElement.ariaOwnsElements": null,
  "HTMLTableElement.firstElementChild": null,
  "HTMLTableElement.lastElementChild": null,
  "HTMLTableElement.previousElementSibling": null,
  "HTMLTableElement.nextElementSibling": null,
  "HTMLTableElement.scrollParent": null,
  "HTMLTableElement.offsetParent": null,
  "HTMLTableElement.caption": "caption",
  "HTMLTableElement.tHead": "tbody",
  "HTMLTableElement.tFoot": "tbody",
  "HTMLTableRowElement.ownerDocument": null,
  "HTMLTableRowElement.parentNode": null,
  "HTMLTableRowElement.parentElement": null,
  "HTMLTableRowElement.childNodes": null,
  "HTMLTableRowElement.firstChild": null,
  "HTMLTableRowElement.lastChild": null,
  "HTMLTableRowElement.previousSibling": null,
  "HTMLTableRowElement.nextSibling": null,
  "HTMLTableRowElement.attributes": null,
  "HTMLTableRowElement.shadowRoot": null,
  "HTMLTableRowElement.assignedSlot": "slot",
  "HTMLTableRowElement.customElementRegistry": null,
  "HTMLTableRowElement.ariaActiveDescendantElement": null,
  "HTMLTableRowElement.ariaControlsElements": null,
  "HTMLTableRowElement.ariaDescribedByElements": null,
  "HTMLTableRowElement.ariaDetailsElements": null,
  "HTMLTableRowElement.ariaErrorMessageElements": null,
  "HTMLTableRowElement.ariaFlowToElements": null,
  "HTMLTableRowElement.ariaLabelledByElements": null,
  "HTMLTableRowElement.ariaOwnsElements": null,
  "HTMLTableRowElement.firstElementChild": null,
  "HTMLTableRowElement.lastElementChild": null,
  "HTMLTableRowElement.previousElementSibling": null,
  "HTMLTableRowElement.nextElementSibling": null,
  "HTMLTableRowElement.scrollParent": null,
  "HTMLTableRowElement.offsetParent": null,
  "HTMLTableSectionElement.ownerDocument": null,
  "HTMLTableSectionElement.parentNode": null,
  "HTMLTableSectionElement.parentElement": null,
  "HTMLTableSectionElement.childNodes": null,
  "HTMLTableSectionElement.firstChild": null,
  "HTMLTableSectionElement.lastChild": null,
  "HTMLTableSectionElement.previousSibling": null,
  "HTMLTableSectionElement.nextSibling": null,
  "HTMLTableSectionElement.attributes": null,
  "HTMLTableSectionElement.shadowRoot": null,
  "HTMLTableSectionElement.assignedSlot": "slot",
  "HTMLTableSectionElement.customElementRegistry": null,
  "HTMLTableSectionElement.ariaActiveDescendantElement": null,
  "HTMLTableSectionElement.ariaControlsElements": null,
  "HTMLTableSectionElement.ariaDescribedByElements": null,
  "HTMLTableSectionElement.ariaDetailsElements": null,
  "HTMLTableSectionElement.ariaErrorMessageElements": null,
  "HTMLTableSectionElement.ariaFlowToElements": null,
  "HTMLTableSectionElement.ariaLabelledByElements": null,
  "HTMLTableSectionElement.ariaOwnsElements": null,
  "HTMLTableSectionElement.firstElementChild": null,
  "HTMLTableSectionElement.lastElementChild": null,
  "HTMLTableSectionElement.previousElementSibling": null,
  "HTMLTableSectionElement.nextElementSibling": null,
  "HTMLTableSectionElement.scrollParent": null,
  "HTMLTableSectionElement.offsetParent": null,
  "HTMLTemplateElement.ownerDocument": null,
  "HTMLTemplateElement.parentNode": null,
  "HTMLTemplateElement.parentElement": null,
  "HTMLTemplateElement.childNodes": null,
  "HTMLTemplateElement.firstChild": null,
  "HTMLTemplateElement.lastChild": null,
  "HTMLTemplateElement.previousSibling": null,
  "HTMLTemplateElement.nextSibling": null,
  "HTMLTemplateElement.attributes": null,
  "HTMLTemplateElement.shadowRoot": null,
  "HTMLTemplateElement.assignedSlot": "slot",
  "HTMLTemplateElement.customElementRegistry": null,
  "HTMLTemplateElement.ariaActiveDescendantElement": null,
  "HTMLTemplateElement.ariaControlsElements": null,
  "HTMLTemplateElement.ariaDescribedByElements": null,
  "HTMLTemplateElement.ariaDetailsElements": null,
  "HTMLTemplateElement.ariaErrorMessageElements": null,
  "HTMLTemplateElement.ariaFlowToElements": null,
  "HTMLTemplateElement.ariaLabelledByElements": null,
  "HTMLTemplateElement.ariaOwnsElements": null,
  "HTMLTemplateElement.firstElementChild": null,
  "HTMLTemplateElement.lastElementChild": null,
  "HTMLTemplateElement.previousElementSibling": null,
  "HTMLTemplateElement.nextElementSibling": null,
  "HTMLTemplateElement.scrollParent": null,
  "HTMLTemplateElement.offsetParent": null,
  "HTMLTemplateElement.content": null,
  "HTMLTimeElement.ownerDocument": null,
  "HTMLTimeElement.parentNode": null,
  "HTMLTimeElement.parentElement": null,
  "HTMLTimeElement.childNodes": null,
  "HTMLTimeElement.firstChild": null,
  "HTMLTimeElement.lastChild": null,
  "HTMLTimeElement.previousSibling": null,
  "HTMLTimeElement.nextSibling": null,
  "HTMLTimeElement.attributes": null,
  "HTMLTimeElement.shadowRoot": null,
  "HTMLTimeElement.assignedSlot": "slot",
  "HTMLTimeElement.customElementRegistry": null,
  "HTMLTimeElement.ariaActiveDescendantElement": null,
  "HTMLTimeElement.ariaControlsElements": null,
  "HTMLTimeElement.ariaDescribedByElements": null,
  "HTMLTimeElement.ariaDetailsElements": null,
  "HTMLTimeElement.ariaErrorMessageElements": null,
  "HTMLTimeElement.ariaFlowToElements": null,
  "HTMLTimeElement.ariaLabelledByElements": null,
  "HTMLTimeElement.ariaOwnsElements": null,
  "HTMLTimeElement.firstElementChild": null,
  "HTMLTimeElement.lastElementChild": null,
  "HTMLTimeElement.previousElementSibling": null,
  "HTMLTimeElement.nextElementSibling": null,
  "HTMLTimeElement.scrollParent": null,
  "HTMLTimeElement.offsetParent": null,
  "HTMLTitleElement.ownerDocument": null,
  "HTMLTitleElement.parentNode": null,
  "HTMLTitleElement.parentElement": null,
  "HTMLTitleElement.childNodes": null,
  "HTMLTitleElement.firstChild": null,
  "HTMLTitleElement.lastChild": null,
  "HTMLTitleElement.previousSibling": null,
  "HTMLTitleElement.nextSibling": null,
  "HTMLTitleElement.attributes": null,
  "HTMLTitleElement.shadowRoot": null,
  "HTMLTitleElement.assignedSlot": "slot",
  "HTMLTitleElement.customElementRegistry": null,
  "HTMLTitleElement.ariaActiveDescendantElement": null,
  "HTMLTitleElement.ariaControlsElements": null,
  "HTMLTitleElement.ariaDescribedByElements": null,
  "HTMLTitleElement.ariaDetailsElements": null,
  "HTMLTitleElement.ariaErrorMessageElements": null,
  "HTMLTitleElement.ariaFlowToElements": null,
  "HTMLTitleElement.ariaLabelledByElements": null,
  "HTMLTitleElement.ariaOwnsElements": null,
  "HTMLTitleElement.firstElementChild": null,
  "HTMLTitleElement.lastElementChild": null,
  "HTMLTitleElement.previousElementSibling": null,
  "HTMLTitleElement.nextElementSibling": null,
  "HTMLTitleElement.scrollParent": null,
  "HTMLTitleElement.offsetParent": null,
  "HTMLUListElement.ownerDocument": null,
  "HTMLUListElement.parentNode": null,
  "HTMLUListElement.parentElement": null,
  "HTMLUListElement.childNodes": null,
  "HTMLUListElement.firstChild": null,
  "HTMLUListElement.lastChild": null,
  "HTMLUListElement.previousSibling": null,
  "HTMLUListElement.nextSibling": null,
  "HTMLUListElement.attributes": null,
  "HTMLUListElement.shadowRoot": null,
  "HTMLUListElement.assignedSlot": "slot",
  "HTMLUListElement.customElementRegistry": null,
  "HTMLUListElement.ariaActiveDescendantElement": null,
  "HTMLUListElement.ariaControlsElements": null,
  "HTMLUListElement.ariaDescribedByElements": null,
  "HTMLUListElement.ariaDetailsElements": null,
  "HTMLUListElement.ariaErrorMessageElements": null,
  "HTMLUListElement.ariaFlowToElements": null,
  "HTMLUListElement.ariaLabelledByElements": null,
  "HTMLUListElement.ariaOwnsElements": null,
  "HTMLUListElement.firstElementChild": null,
  "HTMLUListElement.lastElementChild": null,
  "HTMLUListElement.previousElementSibling": null,
  "HTMLUListElement.nextElementSibling": null,
  "HTMLUListElement.scrollParent": null,
  "HTMLUListElement.offsetParent": null,
  "HTMLUnknownElement.ownerDocument": null,
  "HTMLUnknownElement.parentNode": null,
  "HTMLUnknownElement.parentElement": null,
  "HTMLUnknownElement.childNodes": null,
  "HTMLUnknownElement.firstChild": null,
  "HTMLUnknownElement.lastChild": null,
  "HTMLUnknownElement.previousSibling": null,
  "HTMLUnknownElement.nextSibling": null,
  "HTMLUnknownElement.attributes": null,
  "HTMLUnknownElement.shadowRoot": null,
  "HTMLUnknownElement.assignedSlot": "slot",
  "HTMLUnknownElement.customElementRegistry": null,
  "HTMLUnknownElement.ariaActiveDescendantElement": null,
  "HTMLUnknownElement.ariaControlsElements": null,
  "HTMLUnknownElement.ariaDescribedByElements": null,
  "HTMLUnknownElement.ariaDetailsElements": null,
  "HTMLUnknownElement.ariaErrorMessageElements": null,
  "HTMLUnknownElement.ariaFlowToElements": null,
  "HTMLUnknownElement.ariaLabelledByElements": null,
  "HTMLUnknownElement.ariaOwnsElements": null,
  "HTMLUnknownElement.firstElementChild": null,
  "HTMLUnknownElement.lastElementChild": null,
  "HTMLUnknownElement.previousElementSibling": null,
  "HTMLUnknownElement.nextElementSibling": null,
  "HTMLUnknownElement.scrollParent": null,
  "HTMLUnknownElement.offsetParent": null,
  "HTMLUserMediaElement.ownerDocument": null,
  "HTMLUserMediaElement.parentNode": null,
  "HTMLUserMediaElement.parentElement": null,
  "HTMLUserMediaElement.childNodes": null,
  "HTMLUserMediaElement.firstChild": null,
  "HTMLUserMediaElement.lastChild": null,
  "HTMLUserMediaElement.previousSibling": null,
  "HTMLUserMediaElement.nextSibling": null,
  "HTMLUserMediaElement.attributes": null,
  "HTMLUserMediaElement.shadowRoot": null,
  "HTMLUserMediaElement.assignedSlot": "slot",
  "HTMLUserMediaElement.customElementRegistry": null,
  "HTMLUserMediaElement.ariaActiveDescendantElement": null,
  "HTMLUserMediaElement.ariaControlsElements": null,
  "HTMLUserMediaElement.ariaDescribedByElements": null,
  "HTMLUserMediaElement.ariaDetailsElements": null,
  "HTMLUserMediaElement.ariaErrorMessageElements": null,
  "HTMLUserMediaElement.ariaFlowToElements": null,
  "HTMLUserMediaElement.ariaLabelledByElements": null,
  "HTMLUserMediaElement.ariaOwnsElements": null,
  "HTMLUserMediaElement.firstElementChild": null,
  "HTMLUserMediaElement.lastElementChild": null,
  "HTMLUserMediaElement.previousElementSibling": null,
  "HTMLUserMediaElement.nextElementSibling": null,
  "HTMLUserMediaElement.scrollParent": null,
  "HTMLUserMediaElement.offsetParent": null,
  "HTMLAudioElement.ownerDocument": null,
  "HTMLAudioElement.parentNode": null,
  "HTMLAudioElement.parentElement": null,
  "HTMLAudioElement.childNodes": null,
  "HTMLAudioElement.firstChild": null,
  "HTMLAudioElement.lastChild": null,
  "HTMLAudioElement.previousSibling": null,
  "HTMLAudioElement.nextSibling": null,
  "HTMLAudioElement.attributes": null,
  "HTMLAudioElement.shadowRoot": null,
  "HTMLAudioElement.assignedSlot": "slot",
  "HTMLAudioElement.customElementRegistry": null,
  "HTMLAudioElement.ariaActiveDescendantElement": null,
  "HTMLAudioElement.ariaControlsElements": null,
  "HTMLAudioElement.ariaDescribedByElements": null,
  "HTMLAudioElement.ariaDetailsElements": null,
  "HTMLAudioElement.ariaErrorMessageElements": null,
  "HTMLAudioElement.ariaFlowToElements": null,
  "HTMLAudioElement.ariaLabelledByElements": null,
  "HTMLAudioElement.ariaOwnsElements": null,
  "HTMLAudioElement.firstElementChild": null,
  "HTMLAudioElement.lastElementChild": null,
  "HTMLAudioElement.previousElementSibling": null,
  "HTMLAudioElement.nextElementSibling": null,
  "HTMLAudioElement.scrollParent": null,
  "HTMLAudioElement.offsetParent": null,
  "HTMLMediaElement.ownerDocument": null,
  "HTMLMediaElement.parentNode": null,
  "HTMLMediaElement.parentElement": null,
  "HTMLMediaElement.childNodes": null,
  "HTMLMediaElement.firstChild": null,
  "HTMLMediaElement.lastChild": null,
  "HTMLMediaElement.previousSibling": null,
  "HTMLMediaElement.nextSibling": null,
  "HTMLMediaElement.attributes": null,
  "HTMLMediaElement.shadowRoot": null,
  "HTMLMediaElement.assignedSlot": "slot",
  "HTMLMediaElement.customElementRegistry": null,
  "HTMLMediaElement.ariaActiveDescendantElement": null,
  "HTMLMediaElement.ariaControlsElements": null,
  "HTMLMediaElement.ariaDescribedByElements": null,
  "HTMLMediaElement.ariaDetailsElements": null,
  "HTMLMediaElement.ariaErrorMessageElements": null,
  "HTMLMediaElement.ariaFlowToElements": null,
  "HTMLMediaElement.ariaLabelledByElements": null,
  "HTMLMediaElement.ariaOwnsElements": null,
  "HTMLMediaElement.firstElementChild": null,
  "HTMLMediaElement.lastElementChild": null,
  "HTMLMediaElement.previousElementSibling": null,
  "HTMLMediaElement.nextElementSibling": null,
  "HTMLMediaElement.scrollParent": null,
  "HTMLMediaElement.offsetParent": null,
  "HTMLVideoElement.ownerDocument": null,
  "HTMLVideoElement.parentNode": null,
  "HTMLVideoElement.parentElement": null,
  "HTMLVideoElement.childNodes": null,
  "HTMLVideoElement.firstChild": null,
  "HTMLVideoElement.lastChild": null,
  "HTMLVideoElement.previousSibling": null,
  "HTMLVideoElement.nextSibling": null,
  "HTMLVideoElement.attributes": null,
  "HTMLVideoElement.shadowRoot": null,
  "HTMLVideoElement.assignedSlot": "slot",
  "HTMLVideoElement.customElementRegistry": null,
  "HTMLVideoElement.ariaActiveDescendantElement": null,
  "HTMLVideoElement.ariaControlsElements": null,
  "HTMLVideoElement.ariaDescribedByElements": null,
  "HTMLVideoElement.ariaDetailsElements": null,
  "HTMLVideoElement.ariaErrorMessageElements": null,
  "HTMLVideoElement.ariaFlowToElements": null,
  "HTMLVideoElement.ariaLabelledByElements": null,
  "HTMLVideoElement.ariaOwnsElements": null,
  "HTMLVideoElement.firstElementChild": null,
  "HTMLVideoElement.lastElementChild": null,
  "HTMLVideoElement.previousElementSibling": null,
  "HTMLVideoElement.nextElementSibling": null,
  "HTMLVideoElement.scrollParent": null,
  "HTMLVideoElement.offsetParent": null,
  "HTMLTrackElement.ownerDocument": null,
  "HTMLTrackElement.parentNode": null,
  "HTMLTrackElement.parentElement": null,
  "HTMLTrackElement.childNodes": null,
  "HTMLTrackElement.firstChild": null,
  "HTMLTrackElement.lastChild": null,
  "HTMLTrackElement.previousSibling": null,
  "HTMLTrackElement.nextSibling": null,
  "HTMLTrackElement.attributes": null,
  "HTMLTrackElement.shadowRoot": null,
  "HTMLTrackElement.assignedSlot": "slot",
  "HTMLTrackElement.customElementRegistry": null,
  "HTMLTrackElement.ariaActiveDescendantElement": null,
  "HTMLTrackElement.ariaControlsElements": null,
  "HTMLTrackElement.ariaDescribedByElements": null,
  "HTMLTrackElement.ariaDetailsElements": null,
  "HTMLTrackElement.ariaErrorMessageElements": null,
  "HTMLTrackElement.ariaFlowToElements": null,
  "HTMLTrackElement.ariaLabelledByElements": null,
  "HTMLTrackElement.ariaOwnsElements": null,
  "HTMLTrackElement.firstElementChild": null,
  "HTMLTrackElement.lastElementChild": null,
  "HTMLTrackElement.previousElementSibling": null,
  "HTMLTrackElement.nextElementSibling": null,
  "HTMLTrackElement.scrollParent": null,
  "HTMLTrackElement.offsetParent": null,
  "IntersectionObserver.root": null,
  "IntersectionObserverEntry.target": null,
  "MathMLElement.ownerDocument": null,
  "MathMLElement.parentNode": null,
  "MathMLElement.parentElement": null,
  "MathMLElement.childNodes": null,
  "MathMLElement.firstChild": null,
  "MathMLElement.lastChild": null,
  "MathMLElement.previousSibling": null,
  "MathMLElement.nextSibling": null,
  "MathMLElement.attributes": null,
  "MathMLElement.shadowRoot": null,
  "MathMLElement.assignedSlot": "slot",
  "MathMLElement.customElementRegistry": null,
  "MathMLElement.ariaActiveDescendantElement": null,
  "MathMLElement.ariaControlsElements": null,
  "MathMLElement.ariaDescribedByElements": null,
  "MathMLElement.ariaDetailsElements": null,
  "MathMLElement.ariaErrorMessageElements": null,
  "MathMLElement.ariaFlowToElements": null,
  "MathMLElement.ariaLabelledByElements": null,
  "MathMLElement.ariaOwnsElements": null,
  "MathMLElement.firstElementChild": null,
  "MathMLElement.lastElementChild": null,
  "MathMLElement.previousElementSibling": null,
  "MathMLElement.nextElementSibling": null,
  "NavigateEvent.sourceElement": null,
  "OverscrollEvent.overscrollElement": null,
  "ResizeObserverEntry.target": null,
  "SnapEvent.snapTargetBlock": null,
  "SnapEvent.snapTargetInline": null,
  "SVGAnimateElement.ownerDocument": null,
  "SVGAnimateElement.parentNode": null,
  "SVGAnimateElement.parentElement": null,
  "SVGAnimateElement.childNodes": null,
  "SVGAnimateElement.firstChild": null,
  "SVGAnimateElement.lastChild": null,
  "SVGAnimateElement.previousSibling": null,
  "SVGAnimateElement.nextSibling": null,
  "SVGAnimateElement.attributes": null,
  "SVGAnimateElement.shadowRoot": null,
  "SVGAnimateElement.assignedSlot": "slot",
  "SVGAnimateElement.customElementRegistry": null,
  "SVGAnimateElement.ariaActiveDescendantElement": null,
  "SVGAnimateElement.ariaControlsElements": null,
  "SVGAnimateElement.ariaDescribedByElements": null,
  "SVGAnimateElement.ariaDetailsElements": null,
  "SVGAnimateElement.ariaErrorMessageElements": null,
  "SVGAnimateElement.ariaFlowToElements": null,
  "SVGAnimateElement.ariaLabelledByElements": null,
  "SVGAnimateElement.ariaOwnsElements": null,
  "SVGAnimateElement.firstElementChild": null,
  "SVGAnimateElement.lastElementChild": null,
  "SVGAnimateElement.previousElementSibling": null,
  "SVGAnimateElement.nextElementSibling": null,
  "SVGAnimateElement.ownerSVGElement": null,
  "SVGAnimateElement.viewportElement": null,
  "SVGAnimateElement.targetElement": null,
  "SVGAnimateMotionElement.ownerDocument": null,
  "SVGAnimateMotionElement.parentNode": null,
  "SVGAnimateMotionElement.parentElement": null,
  "SVGAnimateMotionElement.childNodes": null,
  "SVGAnimateMotionElement.firstChild": null,
  "SVGAnimateMotionElement.lastChild": null,
  "SVGAnimateMotionElement.previousSibling": null,
  "SVGAnimateMotionElement.nextSibling": null,
  "SVGAnimateMotionElement.attributes": null,
  "SVGAnimateMotionElement.shadowRoot": null,
  "SVGAnimateMotionElement.assignedSlot": "slot",
  "SVGAnimateMotionElement.customElementRegistry": null,
  "SVGAnimateMotionElement.ariaActiveDescendantElement": null,
  "SVGAnimateMotionElement.ariaControlsElements": null,
  "SVGAnimateMotionElement.ariaDescribedByElements": null,
  "SVGAnimateMotionElement.ariaDetailsElements": null,
  "SVGAnimateMotionElement.ariaErrorMessageElements": null,
  "SVGAnimateMotionElement.ariaFlowToElements": null,
  "SVGAnimateMotionElement.ariaLabelledByElements": null,
  "SVGAnimateMotionElement.ariaOwnsElements": null,
  "SVGAnimateMotionElement.firstElementChild": null,
  "SVGAnimateMotionElement.lastElementChild": null,
  "SVGAnimateMotionElement.previousElementSibling": null,
  "SVGAnimateMotionElement.nextElementSibling": null,
  "SVGAnimateMotionElement.ownerSVGElement": null,
  "SVGAnimateMotionElement.viewportElement": null,
  "SVGAnimateMotionElement.targetElement": null,
  "SVGAnimateTransformElement.ownerDocument": null,
  "SVGAnimateTransformElement.parentNode": null,
  "SVGAnimateTransformElement.parentElement": null,
  "SVGAnimateTransformElement.childNodes": null,
  "SVGAnimateTransformElement.firstChild": null,
  "SVGAnimateTransformElement.lastChild": null,
  "SVGAnimateTransformElement.previousSibling": null,
  "SVGAnimateTransformElement.nextSibling": null,
  "SVGAnimateTransformElement.attributes": null,
  "SVGAnimateTransformElement.shadowRoot": null,
  "SVGAnimateTransformElement.assignedSlot": "slot",
  "SVGAnimateTransformElement.customElementRegistry": null,
  "SVGAnimateTransformElement.ariaActiveDescendantElement": null,
  "SVGAnimateTransformElement.ariaControlsElements": null,
  "SVGAnimateTransformElement.ariaDescribedByElements": null,
  "SVGAnimateTransformElement.ariaDetailsElements": null,
  "SVGAnimateTransformElement.ariaErrorMessageElements": null,
  "SVGAnimateTransformElement.ariaFlowToElements": null,
  "SVGAnimateTransformElement.ariaLabelledByElements": null,
  "SVGAnimateTransformElement.ariaOwnsElements": null,
  "SVGAnimateTransformElement.firstElementChild": null,
  "SVGAnimateTransformElement.lastElementChild": null,
  "SVGAnimateTransformElement.previousElementSibling": null,
  "SVGAnimateTransformElement.nextElementSibling": null,
  "SVGAnimateTransformElement.ownerSVGElement": null,
  "SVGAnimateTransformElement.viewportElement": null,
  "SVGAnimateTransformElement.targetElement": null,
  "SVGAnimationElement.ownerDocument": null,
  "SVGAnimationElement.parentNode": null,
  "SVGAnimationElement.parentElement": null,
  "SVGAnimationElement.childNodes": null,
  "SVGAnimationElement.firstChild": null,
  "SVGAnimationElement.lastChild": null,
  "SVGAnimationElement.previousSibling": null,
  "SVGAnimationElement.nextSibling": null,
  "SVGAnimationElement.attributes": null,
  "SVGAnimationElement.shadowRoot": null,
  "SVGAnimationElement.assignedSlot": "slot",
  "SVGAnimationElement.customElementRegistry": null,
  "SVGAnimationElement.ariaActiveDescendantElement": null,
  "SVGAnimationElement.ariaControlsElements": null,
  "SVGAnimationElement.ariaDescribedByElements": null,
  "SVGAnimationElement.ariaDetailsElements": null,
  "SVGAnimationElement.ariaErrorMessageElements": null,
  "SVGAnimationElement.ariaFlowToElements": null,
  "SVGAnimationElement.ariaLabelledByElements": null,
  "SVGAnimationElement.ariaOwnsElements": null,
  "SVGAnimationElement.firstElementChild": null,
  "SVGAnimationElement.lastElementChild": null,
  "SVGAnimationElement.previousElementSibling": null,
  "SVGAnimationElement.nextElementSibling": null,
  "SVGAnimationElement.ownerSVGElement": null,
  "SVGAnimationElement.viewportElement": null,
  "SVGAnimationElement.targetElement": null,
  "SVGAElement.ownerDocument": null,
  "SVGAElement.parentNode": null,
  "SVGAElement.parentElement": null,
  "SVGAElement.childNodes": null,
  "SVGAElement.firstChild": null,
  "SVGAElement.lastChild": null,
  "SVGAElement.previousSibling": null,
  "SVGAElement.nextSibling": null,
  "SVGAElement.attributes": null,
  "SVGAElement.shadowRoot": null,
  "SVGAElement.assignedSlot": "slot",
  "SVGAElement.customElementRegistry": null,
  "SVGAElement.ariaActiveDescendantElement": null,
  "SVGAElement.ariaControlsElements": null,
  "SVGAElement.ariaDescribedByElements": null,
  "SVGAElement.ariaDetailsElements": null,
  "SVGAElement.ariaErrorMessageElements": null,
  "SVGAElement.ariaFlowToElements": null,
  "SVGAElement.ariaLabelledByElements": null,
  "SVGAElement.ariaOwnsElements": null,
  "SVGAElement.firstElementChild": null,
  "SVGAElement.lastElementChild": null,
  "SVGAElement.previousElementSibling": null,
  "SVGAElement.nextElementSibling": null,
  "SVGAElement.ownerSVGElement": null,
  "SVGAElement.viewportElement": null,
  "SVGAElement.nearestViewportElement": null,
  "SVGAElement.farthestViewportElement": null,
  "SVGAElement.interestForElement": null,
  "SVGCircleElement.ownerDocument": null,
  "SVGCircleElement.parentNode": null,
  "SVGCircleElement.parentElement": null,
  "SVGCircleElement.childNodes": null,
  "SVGCircleElement.firstChild": null,
  "SVGCircleElement.lastChild": null,
  "SVGCircleElement.previousSibling": null,
  "SVGCircleElement.nextSibling": null,
  "SVGCircleElement.attributes": null,
  "SVGCircleElement.shadowRoot": null,
  "SVGCircleElement.assignedSlot": "slot",
  "SVGCircleElement.customElementRegistry": null,
  "SVGCircleElement.ariaActiveDescendantElement": null,
  "SVGCircleElement.ariaControlsElements": null,
  "SVGCircleElement.ariaDescribedByElements": null,
  "SVGCircleElement.ariaDetailsElements": null,
  "SVGCircleElement.ariaErrorMessageElements": null,
  "SVGCircleElement.ariaFlowToElements": null,
  "SVGCircleElement.ariaLabelledByElements": null,
  "SVGCircleElement.ariaOwnsElements": null,
  "SVGCircleElement.firstElementChild": null,
  "SVGCircleElement.lastElementChild": null,
  "SVGCircleElement.previousElementSibling": null,
  "SVGCircleElement.nextElementSibling": null,
  "SVGCircleElement.ownerSVGElement": null,
  "SVGCircleElement.viewportElement": null,
  "SVGCircleElement.nearestViewportElement": null,
  "SVGCircleElement.farthestViewportElement": null,
  "SVGClipPathElement.ownerDocument": null,
  "SVGClipPathElement.parentNode": null,
  "SVGClipPathElement.parentElement": null,
  "SVGClipPathElement.childNodes": null,
  "SVGClipPathElement.firstChild": null,
  "SVGClipPathElement.lastChild": null,
  "SVGClipPathElement.previousSibling": null,
  "SVGClipPathElement.nextSibling": null,
  "SVGClipPathElement.attributes": null,
  "SVGClipPathElement.shadowRoot": null,
  "SVGClipPathElement.assignedSlot": "slot",
  "SVGClipPathElement.customElementRegistry": null,
  "SVGClipPathElement.ariaActiveDescendantElement": null,
  "SVGClipPathElement.ariaControlsElements": null,
  "SVGClipPathElement.ariaDescribedByElements": null,
  "SVGClipPathElement.ariaDetailsElements": null,
  "SVGClipPathElement.ariaErrorMessageElements": null,
  "SVGClipPathElement.ariaFlowToElements": null,
  "SVGClipPathElement.ariaLabelledByElements": null,
  "SVGClipPathElement.ariaOwnsElements": null,
  "SVGClipPathElement.firstElementChild": null,
  "SVGClipPathElement.lastElementChild": null,
  "SVGClipPathElement.previousElementSibling": null,
  "SVGClipPathElement.nextElementSibling": null,
  "SVGClipPathElement.ownerSVGElement": null,
  "SVGClipPathElement.viewportElement": null,
  "SVGComponentTransferFunctionElement.ownerDocument": null,
  "SVGComponentTransferFunctionElement.parentNode": null,
  "SVGComponentTransferFunctionElement.parentElement": null,
  "SVGComponentTransferFunctionElement.childNodes": null,
  "SVGComponentTransferFunctionElement.firstChild": null,
  "SVGComponentTransferFunctionElement.lastChild": null,
  "SVGComponentTransferFunctionElement.previousSibling": null,
  "SVGComponentTransferFunctionElement.nextSibling": null,
  "SVGComponentTransferFunctionElement.attributes": null,
  "SVGComponentTransferFunctionElement.shadowRoot": null,
  "SVGComponentTransferFunctionElement.assignedSlot": "slot",
  "SVGComponentTransferFunctionElement.customElementRegistry": null,
  "SVGComponentTransferFunctionElement.ariaActiveDescendantElement": null,
  "SVGComponentTransferFunctionElement.ariaControlsElements": null,
  "SVGComponentTransferFunctionElement.ariaDescribedByElements": null,
  "SVGComponentTransferFunctionElement.ariaDetailsElements": null,
  "SVGComponentTransferFunctionElement.ariaErrorMessageElements": null,
  "SVGComponentTransferFunctionElement.ariaFlowToElements": null,
  "SVGComponentTransferFunctionElement.ariaLabelledByElements": null,
  "SVGComponentTransferFunctionElement.ariaOwnsElements": null,
  "SVGComponentTransferFunctionElement.firstElementChild": null,
  "SVGComponentTransferFunctionElement.lastElementChild": null,
  "SVGComponentTransferFunctionElement.previousElementSibling": null,
  "SVGComponentTransferFunctionElement.nextElementSibling": null,
  "SVGComponentTransferFunctionElement.ownerSVGElement": null,
  "SVGComponentTransferFunctionElement.viewportElement": null,
  "SVGDefsElement.ownerDocument": null,
  "SVGDefsElement.parentNode": null,
  "SVGDefsElement.parentElement": null,
  "SVGDefsElement.childNodes": null,
  "SVGDefsElement.firstChild": null,
  "SVGDefsElement.lastChild": null,
  "SVGDefsElement.previousSibling": null,
  "SVGDefsElement.nextSibling": null,
  "SVGDefsElement.attributes": null,
  "SVGDefsElement.shadowRoot": null,
  "SVGDefsElement.assignedSlot": "slot",
  "SVGDefsElement.customElementRegistry": null,
  "SVGDefsElement.ariaActiveDescendantElement": null,
  "SVGDefsElement.ariaControlsElements": null,
  "SVGDefsElement.ariaDescribedByElements": null,
  "SVGDefsElement.ariaDetailsElements": null,
  "SVGDefsElement.ariaErrorMessageElements": null,
  "SVGDefsElement.ariaFlowToElements": null,
  "SVGDefsElement.ariaLabelledByElements": null,
  "SVGDefsElement.ariaOwnsElements": null,
  "SVGDefsElement.firstElementChild": null,
  "SVGDefsElement.lastElementChild": null,
  "SVGDefsElement.previousElementSibling": null,
  "SVGDefsElement.nextElementSibling": null,
  "SVGDefsElement.ownerSVGElement": null,
  "SVGDefsElement.viewportElement": null,
  "SVGDefsElement.nearestViewportElement": null,
  "SVGDefsElement.farthestViewportElement": null,
  "SVGDescElement.ownerDocument": null,
  "SVGDescElement.parentNode": null,
  "SVGDescElement.parentElement": null,
  "SVGDescElement.childNodes": null,
  "SVGDescElement.firstChild": null,
  "SVGDescElement.lastChild": null,
  "SVGDescElement.previousSibling": null,
  "SVGDescElement.nextSibling": null,
  "SVGDescElement.attributes": null,
  "SVGDescElement.shadowRoot": null,
  "SVGDescElement.assignedSlot": "slot",
  "SVGDescElement.customElementRegistry": null,
  "SVGDescElement.ariaActiveDescendantElement": null,
  "SVGDescElement.ariaControlsElements": null,
  "SVGDescElement.ariaDescribedByElements": null,
  "SVGDescElement.ariaDetailsElements": null,
  "SVGDescElement.ariaErrorMessageElements": null,
  "SVGDescElement.ariaFlowToElements": null,
  "SVGDescElement.ariaLabelledByElements": null,
  "SVGDescElement.ariaOwnsElements": null,
  "SVGDescElement.firstElementChild": null,
  "SVGDescElement.lastElementChild": null,
  "SVGDescElement.previousElementSibling": null,
  "SVGDescElement.nextElementSibling": null,
  "SVGDescElement.ownerSVGElement": null,
  "SVGDescElement.viewportElement": null,
  "SVGElement.ownerDocument": null,
  "SVGElement.parentNode": null,
  "SVGElement.parentElement": null,
  "SVGElement.childNodes": null,
  "SVGElement.firstChild": null,
  "SVGElement.lastChild": null,
  "SVGElement.previousSibling": null,
  "SVGElement.nextSibling": null,
  "SVGElement.attributes": null,
  "SVGElement.shadowRoot": null,
  "SVGElement.assignedSlot": "slot",
  "SVGElement.customElementRegistry": null,
  "SVGElement.ariaActiveDescendantElement": null,
  "SVGElement.ariaControlsElements": null,
  "SVGElement.ariaDescribedByElements": null,
  "SVGElement.ariaDetailsElements": null,
  "SVGElement.ariaErrorMessageElements": null,
  "SVGElement.ariaFlowToElements": null,
  "SVGElement.ariaLabelledByElements": null,
  "SVGElement.ariaOwnsElements": null,
  "SVGElement.firstElementChild": null,
  "SVGElement.lastElementChild": null,
  "SVGElement.previousElementSibling": null,
  "SVGElement.nextElementSibling": null,
  "SVGElement.ownerSVGElement": null,
  "SVGElement.viewportElement": null,
  "SVGEllipseElement.ownerDocument": null,
  "SVGEllipseElement.parentNode": null,
  "SVGEllipseElement.parentElement": null,
  "SVGEllipseElement.childNodes": null,
  "SVGEllipseElement.firstChild": null,
  "SVGEllipseElement.lastChild": null,
  "SVGEllipseElement.previousSibling": null,
  "SVGEllipseElement.nextSibling": null,
  "SVGEllipseElement.attributes": null,
  "SVGEllipseElement.shadowRoot": null,
  "SVGEllipseElement.assignedSlot": "slot",
  "SVGEllipseElement.customElementRegistry": null,
  "SVGEllipseElement.ariaActiveDescendantElement": null,
  "SVGEllipseElement.ariaControlsElements": null,
  "SVGEllipseElement.ariaDescribedByElements": null,
  "SVGEllipseElement.ariaDetailsElements": null,
  "SVGEllipseElement.ariaErrorMessageElements": null,
  "SVGEllipseElement.ariaFlowToElements": null,
  "SVGEllipseElement.ariaLabelledByElements": null,
  "SVGEllipseElement.ariaOwnsElements": null,
  "SVGEllipseElement.firstElementChild": null,
  "SVGEllipseElement.lastElementChild": null,
  "SVGEllipseElement.previousElementSibling": null,
  "SVGEllipseElement.nextElementSibling": null,
  "SVGEllipseElement.ownerSVGElement": null,
  "SVGEllipseElement.viewportElement": null,
  "SVGEllipseElement.nearestViewportElement": null,
  "SVGEllipseElement.farthestViewportElement": null,
  "SVGFEBlendElement.ownerDocument": null,
  "SVGFEBlendElement.parentNode": null,
  "SVGFEBlendElement.parentElement": null,
  "SVGFEBlendElement.childNodes": null,
  "SVGFEBlendElement.firstChild": null,
  "SVGFEBlendElement.lastChild": null,
  "SVGFEBlendElement.previousSibling": null,
  "SVGFEBlendElement.nextSibling": null,
  "SVGFEBlendElement.attributes": null,
  "SVGFEBlendElement.shadowRoot": null,
  "SVGFEBlendElement.assignedSlot": "slot",
  "SVGFEBlendElement.customElementRegistry": null,
  "SVGFEBlendElement.ariaActiveDescendantElement": null,
  "SVGFEBlendElement.ariaControlsElements": null,
  "SVGFEBlendElement.ariaDescribedByElements": null,
  "SVGFEBlendElement.ariaDetailsElements": null,
  "SVGFEBlendElement.ariaErrorMessageElements": null,
  "SVGFEBlendElement.ariaFlowToElements": null,
  "SVGFEBlendElement.ariaLabelledByElements": null,
  "SVGFEBlendElement.ariaOwnsElements": null,
  "SVGFEBlendElement.firstElementChild": null,
  "SVGFEBlendElement.lastElementChild": null,
  "SVGFEBlendElement.previousElementSibling": null,
  "SVGFEBlendElement.nextElementSibling": null,
  "SVGFEBlendElement.ownerSVGElement": null,
  "SVGFEBlendElement.viewportElement": null,
  "SVGFEColorMatrixElement.ownerDocument": null,
  "SVGFEColorMatrixElement.parentNode": null,
  "SVGFEColorMatrixElement.parentElement": null,
  "SVGFEColorMatrixElement.childNodes": null,
  "SVGFEColorMatrixElement.firstChild": null,
  "SVGFEColorMatrixElement.lastChild": null,
  "SVGFEColorMatrixElement.previousSibling": null,
  "SVGFEColorMatrixElement.nextSibling": null,
  "SVGFEColorMatrixElement.attributes": null,
  "SVGFEColorMatrixElement.shadowRoot": null,
  "SVGFEColorMatrixElement.assignedSlot": "slot",
  "SVGFEColorMatrixElement.customElementRegistry": null,
  "SVGFEColorMatrixElement.ariaActiveDescendantElement": null,
  "SVGFEColorMatrixElement.ariaControlsElements": null,
  "SVGFEColorMatrixElement.ariaDescribedByElements": null,
  "SVGFEColorMatrixElement.ariaDetailsElements": null,
  "SVGFEColorMatrixElement.ariaErrorMessageElements": null,
  "SVGFEColorMatrixElement.ariaFlowToElements": null,
  "SVGFEColorMatrixElement.ariaLabelledByElements": null,
  "SVGFEColorMatrixElement.ariaOwnsElements": null,
  "SVGFEColorMatrixElement.firstElementChild": null,
  "SVGFEColorMatrixElement.lastElementChild": null,
  "SVGFEColorMatrixElement.previousElementSibling": null,
  "SVGFEColorMatrixElement.nextElementSibling": null,
  "SVGFEColorMatrixElement.ownerSVGElement": null,
  "SVGFEColorMatrixElement.viewportElement": null,
  "SVGFEComponentTransferElement.ownerDocument": null,
  "SVGFEComponentTransferElement.parentNode": null,
  "SVGFEComponentTransferElement.parentElement": null,
  "SVGFEComponentTransferElement.childNodes": null,
  "SVGFEComponentTransferElement.firstChild": null,
  "SVGFEComponentTransferElement.lastChild": null,
  "SVGFEComponentTransferElement.previousSibling": null,
  "SVGFEComponentTransferElement.nextSibling": null,
  "SVGFEComponentTransferElement.attributes": null,
  "SVGFEComponentTransferElement.shadowRoot": null,
  "SVGFEComponentTransferElement.assignedSlot": "slot",
  "SVGFEComponentTransferElement.customElementRegistry": null,
  "SVGFEComponentTransferElement.ariaActiveDescendantElement": null,
  "SVGFEComponentTransferElement.ariaControlsElements": null,
  "SVGFEComponentTransferElement.ariaDescribedByElements": null,
  "SVGFEComponentTransferElement.ariaDetailsElements": null,
  "SVGFEComponentTransferElement.ariaErrorMessageElements": null,
  "SVGFEComponentTransferElement.ariaFlowToElements": null,
  "SVGFEComponentTransferElement.ariaLabelledByElements": null,
  "SVGFEComponentTransferElement.ariaOwnsElements": null,
  "SVGFEComponentTransferElement.firstElementChild": null,
  "SVGFEComponentTransferElement.lastElementChild": null,
  "SVGFEComponentTransferElement.previousElementSibling": null,
  "SVGFEComponentTransferElement.nextElementSibling": null,
  "SVGFEComponentTransferElement.ownerSVGElement": null,
  "SVGFEComponentTransferElement.viewportElement": null,
  "SVGFECompositeElement.ownerDocument": null,
  "SVGFECompositeElement.parentNode": null,
  "SVGFECompositeElement.parentElement": null,
  "SVGFECompositeElement.childNodes": null,
  "SVGFECompositeElement.firstChild": null,
  "SVGFECompositeElement.lastChild": null,
  "SVGFECompositeElement.previousSibling": null,
  "SVGFECompositeElement.nextSibling": null,
  "SVGFECompositeElement.attributes": null,
  "SVGFECompositeElement.shadowRoot": null,
  "SVGFECompositeElement.assignedSlot": "slot",
  "SVGFECompositeElement.customElementRegistry": null,
  "SVGFECompositeElement.ariaActiveDescendantElement": null,
  "SVGFECompositeElement.ariaControlsElements": null,
  "SVGFECompositeElement.ariaDescribedByElements": null,
  "SVGFECompositeElement.ariaDetailsElements": null,
  "SVGFECompositeElement.ariaErrorMessageElements": null,
  "SVGFECompositeElement.ariaFlowToElements": null,
  "SVGFECompositeElement.ariaLabelledByElements": null,
  "SVGFECompositeElement.ariaOwnsElements": null,
  "SVGFECompositeElement.firstElementChild": null,
  "SVGFECompositeElement.lastElementChild": null,
  "SVGFECompositeElement.previousElementSibling": null,
  "SVGFECompositeElement.nextElementSibling": null,
  "SVGFECompositeElement.ownerSVGElement": null,
  "SVGFECompositeElement.viewportElement": null,
  "SVGFEConvolveMatrixElement.ownerDocument": null,
  "SVGFEConvolveMatrixElement.parentNode": null,
  "SVGFEConvolveMatrixElement.parentElement": null,
  "SVGFEConvolveMatrixElement.childNodes": null,
  "SVGFEConvolveMatrixElement.firstChild": null,
  "SVGFEConvolveMatrixElement.lastChild": null,
  "SVGFEConvolveMatrixElement.previousSibling": null,
  "SVGFEConvolveMatrixElement.nextSibling": null,
  "SVGFEConvolveMatrixElement.attributes": null,
  "SVGFEConvolveMatrixElement.shadowRoot": null,
  "SVGFEConvolveMatrixElement.assignedSlot": "slot",
  "SVGFEConvolveMatrixElement.customElementRegistry": null,
  "SVGFEConvolveMatrixElement.ariaActiveDescendantElement": null,
  "SVGFEConvolveMatrixElement.ariaControlsElements": null,
  "SVGFEConvolveMatrixElement.ariaDescribedByElements": null,
  "SVGFEConvolveMatrixElement.ariaDetailsElements": null,
  "SVGFEConvolveMatrixElement.ariaErrorMessageElements": null,
  "SVGFEConvolveMatrixElement.ariaFlowToElements": null,
  "SVGFEConvolveMatrixElement.ariaLabelledByElements": null,
  "SVGFEConvolveMatrixElement.ariaOwnsElements": null,
  "SVGFEConvolveMatrixElement.firstElementChild": null,
  "SVGFEConvolveMatrixElement.lastElementChild": null,
  "SVGFEConvolveMatrixElement.previousElementSibling": null,
  "SVGFEConvolveMatrixElement.nextElementSibling": null,
  "SVGFEConvolveMatrixElement.ownerSVGElement": null,
  "SVGFEConvolveMatrixElement.viewportElement": null,
  "SVGFEDiffuseLightingElement.ownerDocument": null,
  "SVGFEDiffuseLightingElement.parentNode": null,
  "SVGFEDiffuseLightingElement.parentElement": null,
  "SVGFEDiffuseLightingElement.childNodes": null,
  "SVGFEDiffuseLightingElement.firstChild": null,
  "SVGFEDiffuseLightingElement.lastChild": null,
  "SVGFEDiffuseLightingElement.previousSibling": null,
  "SVGFEDiffuseLightingElement.nextSibling": null,
  "SVGFEDiffuseLightingElement.attributes": null,
  "SVGFEDiffuseLightingElement.shadowRoot": null,
  "SVGFEDiffuseLightingElement.assignedSlot": "slot",
  "SVGFEDiffuseLightingElement.customElementRegistry": null,
  "SVGFEDiffuseLightingElement.ariaActiveDescendantElement": null,
  "SVGFEDiffuseLightingElement.ariaControlsElements": null,
  "SVGFEDiffuseLightingElement.ariaDescribedByElements": null,
  "SVGFEDiffuseLightingElement.ariaDetailsElements": null,
  "SVGFEDiffuseLightingElement.ariaErrorMessageElements": null,
  "SVGFEDiffuseLightingElement.ariaFlowToElements": null,
  "SVGFEDiffuseLightingElement.ariaLabelledByElements": null,
  "SVGFEDiffuseLightingElement.ariaOwnsElements": null,
  "SVGFEDiffuseLightingElement.firstElementChild": null,
  "SVGFEDiffuseLightingElement.lastElementChild": null,
  "SVGFEDiffuseLightingElement.previousElementSibling": null,
  "SVGFEDiffuseLightingElement.nextElementSibling": null,
  "SVGFEDiffuseLightingElement.ownerSVGElement": null,
  "SVGFEDiffuseLightingElement.viewportElement": null,
  "SVGFEDisplacementMapElement.ownerDocument": null,
  "SVGFEDisplacementMapElement.parentNode": null,
  "SVGFEDisplacementMapElement.parentElement": null,
  "SVGFEDisplacementMapElement.childNodes": null,
  "SVGFEDisplacementMapElement.firstChild": null,
  "SVGFEDisplacementMapElement.lastChild": null,
  "SVGFEDisplacementMapElement.previousSibling": null,
  "SVGFEDisplacementMapElement.nextSibling": null,
  "SVGFEDisplacementMapElement.attributes": null,
  "SVGFEDisplacementMapElement.shadowRoot": null,
  "SVGFEDisplacementMapElement.assignedSlot": "slot",
  "SVGFEDisplacementMapElement.customElementRegistry": null,
  "SVGFEDisplacementMapElement.ariaActiveDescendantElement": null,
  "SVGFEDisplacementMapElement.ariaControlsElements": null,
  "SVGFEDisplacementMapElement.ariaDescribedByElements": null,
  "SVGFEDisplacementMapElement.ariaDetailsElements": null,
  "SVGFEDisplacementMapElement.ariaErrorMessageElements": null,
  "SVGFEDisplacementMapElement.ariaFlowToElements": null,
  "SVGFEDisplacementMapElement.ariaLabelledByElements": null,
  "SVGFEDisplacementMapElement.ariaOwnsElements": null,
  "SVGFEDisplacementMapElement.firstElementChild": null,
  "SVGFEDisplacementMapElement.lastElementChild": null,
  "SVGFEDisplacementMapElement.previousElementSibling": null,
  "SVGFEDisplacementMapElement.nextElementSibling": null,
  "SVGFEDisplacementMapElement.ownerSVGElement": null,
  "SVGFEDisplacementMapElement.viewportElement": null,
  "SVGFEDistantLightElement.ownerDocument": null,
  "SVGFEDistantLightElement.parentNode": null,
  "SVGFEDistantLightElement.parentElement": null,
  "SVGFEDistantLightElement.childNodes": null,
  "SVGFEDistantLightElement.firstChild": null,
  "SVGFEDistantLightElement.lastChild": null,
  "SVGFEDistantLightElement.previousSibling": null,
  "SVGFEDistantLightElement.nextSibling": null,
  "SVGFEDistantLightElement.attributes": null,
  "SVGFEDistantLightElement.shadowRoot": null,
  "SVGFEDistantLightElement.assignedSlot": "slot",
  "SVGFEDistantLightElement.customElementRegistry": null,
  "SVGFEDistantLightElement.ariaActiveDescendantElement": null,
  "SVGFEDistantLightElement.ariaControlsElements": null,
  "SVGFEDistantLightElement.ariaDescribedByElements": null,
  "SVGFEDistantLightElement.ariaDetailsElements": null,
  "SVGFEDistantLightElement.ariaErrorMessageElements": null,
  "SVGFEDistantLightElement.ariaFlowToElements": null,
  "SVGFEDistantLightElement.ariaLabelledByElements": null,
  "SVGFEDistantLightElement.ariaOwnsElements": null,
  "SVGFEDistantLightElement.firstElementChild": null,
  "SVGFEDistantLightElement.lastElementChild": null,
  "SVGFEDistantLightElement.previousElementSibling": null,
  "SVGFEDistantLightElement.nextElementSibling": null,
  "SVGFEDistantLightElement.ownerSVGElement": null,
  "SVGFEDistantLightElement.viewportElement": null,
  "SVGFEDropShadowElement.ownerDocument": null,
  "SVGFEDropShadowElement.parentNode": null,
  "SVGFEDropShadowElement.parentElement": null,
  "SVGFEDropShadowElement.childNodes": null,
  "SVGFEDropShadowElement.firstChild": null,
  "SVGFEDropShadowElement.lastChild": null,
  "SVGFEDropShadowElement.previousSibling": null,
  "SVGFEDropShadowElement.nextSibling": null,
  "SVGFEDropShadowElement.attributes": null,
  "SVGFEDropShadowElement.shadowRoot": null,
  "SVGFEDropShadowElement.assignedSlot": "slot",
  "SVGFEDropShadowElement.customElementRegistry": null,
  "SVGFEDropShadowElement.ariaActiveDescendantElement": null,
  "SVGFEDropShadowElement.ariaControlsElements": null,
  "SVGFEDropShadowElement.ariaDescribedByElements": null,
  "SVGFEDropShadowElement.ariaDetailsElements": null,
  "SVGFEDropShadowElement.ariaErrorMessageElements": null,
  "SVGFEDropShadowElement.ariaFlowToElements": null,
  "SVGFEDropShadowElement.ariaLabelledByElements": null,
  "SVGFEDropShadowElement.ariaOwnsElements": null,
  "SVGFEDropShadowElement.firstElementChild": null,
  "SVGFEDropShadowElement.lastElementChild": null,
  "SVGFEDropShadowElement.previousElementSibling": null,
  "SVGFEDropShadowElement.nextElementSibling": null,
  "SVGFEDropShadowElement.ownerSVGElement": null,
  "SVGFEDropShadowElement.viewportElement": null,
  "SVGFEFloodElement.ownerDocument": null,
  "SVGFEFloodElement.parentNode": null,
  "SVGFEFloodElement.parentElement": null,
  "SVGFEFloodElement.childNodes": null,
  "SVGFEFloodElement.firstChild": null,
  "SVGFEFloodElement.lastChild": null,
  "SVGFEFloodElement.previousSibling": null,
  "SVGFEFloodElement.nextSibling": null,
  "SVGFEFloodElement.attributes": null,
  "SVGFEFloodElement.shadowRoot": null,
  "SVGFEFloodElement.assignedSlot": "slot",
  "SVGFEFloodElement.customElementRegistry": null,
  "SVGFEFloodElement.ariaActiveDescendantElement": null,
  "SVGFEFloodElement.ariaControlsElements": null,
  "SVGFEFloodElement.ariaDescribedByElements": null,
  "SVGFEFloodElement.ariaDetailsElements": null,
  "SVGFEFloodElement.ariaErrorMessageElements": null,
  "SVGFEFloodElement.ariaFlowToElements": null,
  "SVGFEFloodElement.ariaLabelledByElements": null,
  "SVGFEFloodElement.ariaOwnsElements": null,
  "SVGFEFloodElement.firstElementChild": null,
  "SVGFEFloodElement.lastElementChild": null,
  "SVGFEFloodElement.previousElementSibling": null,
  "SVGFEFloodElement.nextElementSibling": null,
  "SVGFEFloodElement.ownerSVGElement": null,
  "SVGFEFloodElement.viewportElement": null,
  "SVGFEFuncAElement.ownerDocument": null,
  "SVGFEFuncAElement.parentNode": null,
  "SVGFEFuncAElement.parentElement": null,
  "SVGFEFuncAElement.childNodes": null,
  "SVGFEFuncAElement.firstChild": null,
  "SVGFEFuncAElement.lastChild": null,
  "SVGFEFuncAElement.previousSibling": null,
  "SVGFEFuncAElement.nextSibling": null,
  "SVGFEFuncAElement.attributes": null,
  "SVGFEFuncAElement.shadowRoot": null,
  "SVGFEFuncAElement.assignedSlot": "slot",
  "SVGFEFuncAElement.customElementRegistry": null,
  "SVGFEFuncAElement.ariaActiveDescendantElement": null,
  "SVGFEFuncAElement.ariaControlsElements": null,
  "SVGFEFuncAElement.ariaDescribedByElements": null,
  "SVGFEFuncAElement.ariaDetailsElements": null,
  "SVGFEFuncAElement.ariaErrorMessageElements": null,
  "SVGFEFuncAElement.ariaFlowToElements": null,
  "SVGFEFuncAElement.ariaLabelledByElements": null,
  "SVGFEFuncAElement.ariaOwnsElements": null,
  "SVGFEFuncAElement.firstElementChild": null,
  "SVGFEFuncAElement.lastElementChild": null,
  "SVGFEFuncAElement.previousElementSibling": null,
  "SVGFEFuncAElement.nextElementSibling": null,
  "SVGFEFuncAElement.ownerSVGElement": null,
  "SVGFEFuncAElement.viewportElement": null,
  "SVGFEFuncBElement.ownerDocument": null,
  "SVGFEFuncBElement.parentNode": null,
  "SVGFEFuncBElement.parentElement": null,
  "SVGFEFuncBElement.childNodes": null,
  "SVGFEFuncBElement.firstChild": null,
  "SVGFEFuncBElement.lastChild": null,
  "SVGFEFuncBElement.previousSibling": null,
  "SVGFEFuncBElement.nextSibling": null,
  "SVGFEFuncBElement.attributes": null,
  "SVGFEFuncBElement.shadowRoot": null,
  "SVGFEFuncBElement.assignedSlot": "slot",
  "SVGFEFuncBElement.customElementRegistry": null,
  "SVGFEFuncBElement.ariaActiveDescendantElement": null,
  "SVGFEFuncBElement.ariaControlsElements": null,
  "SVGFEFuncBElement.ariaDescribedByElements": null,
  "SVGFEFuncBElement.ariaDetailsElements": null,
  "SVGFEFuncBElement.ariaErrorMessageElements": null,
  "SVGFEFuncBElement.ariaFlowToElements": null,
  "SVGFEFuncBElement.ariaLabelledByElements": null,
  "SVGFEFuncBElement.ariaOwnsElements": null,
  "SVGFEFuncBElement.firstElementChild": null,
  "SVGFEFuncBElement.lastElementChild": null,
  "SVGFEFuncBElement.previousElementSibling": null,
  "SVGFEFuncBElement.nextElementSibling": null,
  "SVGFEFuncBElement.ownerSVGElement": null,
  "SVGFEFuncBElement.viewportElement": null,
  "SVGFEFuncGElement.ownerDocument": null,
  "SVGFEFuncGElement.parentNode": null,
  "SVGFEFuncGElement.parentElement": null,
  "SVGFEFuncGElement.childNodes": null,
  "SVGFEFuncGElement.firstChild": null,
  "SVGFEFuncGElement.lastChild": null,
  "SVGFEFuncGElement.previousSibling": null,
  "SVGFEFuncGElement.nextSibling": null,
  "SVGFEFuncGElement.attributes": null,
  "SVGFEFuncGElement.shadowRoot": null,
  "SVGFEFuncGElement.assignedSlot": "slot",
  "SVGFEFuncGElement.customElementRegistry": null,
  "SVGFEFuncGElement.ariaActiveDescendantElement": null,
  "SVGFEFuncGElement.ariaControlsElements": null,
  "SVGFEFuncGElement.ariaDescribedByElements": null,
  "SVGFEFuncGElement.ariaDetailsElements": null,
  "SVGFEFuncGElement.ariaErrorMessageElements": null,
  "SVGFEFuncGElement.ariaFlowToElements": null,
  "SVGFEFuncGElement.ariaLabelledByElements": null,
  "SVGFEFuncGElement.ariaOwnsElements": null,
  "SVGFEFuncGElement.firstElementChild": null,
  "SVGFEFuncGElement.lastElementChild": null,
  "SVGFEFuncGElement.previousElementSibling": null,
  "SVGFEFuncGElement.nextElementSibling": null,
  "SVGFEFuncGElement.ownerSVGElement": null,
  "SVGFEFuncGElement.viewportElement": null,
  "SVGFEFuncRElement.ownerDocument": null,
  "SVGFEFuncRElement.parentNode": null,
  "SVGFEFuncRElement.parentElement": null,
  "SVGFEFuncRElement.childNodes": null,
  "SVGFEFuncRElement.firstChild": null,
  "SVGFEFuncRElement.lastChild": null,
  "SVGFEFuncRElement.previousSibling": null,
  "SVGFEFuncRElement.nextSibling": null,
  "SVGFEFuncRElement.attributes": null,
  "SVGFEFuncRElement.shadowRoot": null,
  "SVGFEFuncRElement.assignedSlot": "slot",
  "SVGFEFuncRElement.customElementRegistry": null,
  "SVGFEFuncRElement.ariaActiveDescendantElement": null,
  "SVGFEFuncRElement.ariaControlsElements": null,
  "SVGFEFuncRElement.ariaDescribedByElements": null,
  "SVGFEFuncRElement.ariaDetailsElements": null,
  "SVGFEFuncRElement.ariaErrorMessageElements": null,
  "SVGFEFuncRElement.ariaFlowToElements": null,
  "SVGFEFuncRElement.ariaLabelledByElements": null,
  "SVGFEFuncRElement.ariaOwnsElements": null,
  "SVGFEFuncRElement.firstElementChild": null,
  "SVGFEFuncRElement.lastElementChild": null,
  "SVGFEFuncRElement.previousElementSibling": null,
  "SVGFEFuncRElement.nextElementSibling": null,
  "SVGFEFuncRElement.ownerSVGElement": null,
  "SVGFEFuncRElement.viewportElement": null,
  "SVGFEGaussianBlurElement.ownerDocument": null,
  "SVGFEGaussianBlurElement.parentNode": null,
  "SVGFEGaussianBlurElement.parentElement": null,
  "SVGFEGaussianBlurElement.childNodes": null,
  "SVGFEGaussianBlurElement.firstChild": null,
  "SVGFEGaussianBlurElement.lastChild": null,
  "SVGFEGaussianBlurElement.previousSibling": null,
  "SVGFEGaussianBlurElement.nextSibling": null,
  "SVGFEGaussianBlurElement.attributes": null,
  "SVGFEGaussianBlurElement.shadowRoot": null,
  "SVGFEGaussianBlurElement.assignedSlot": "slot",
  "SVGFEGaussianBlurElement.customElementRegistry": null,
  "SVGFEGaussianBlurElement.ariaActiveDescendantElement": null,
  "SVGFEGaussianBlurElement.ariaControlsElements": null,
  "SVGFEGaussianBlurElement.ariaDescribedByElements": null,
  "SVGFEGaussianBlurElement.ariaDetailsElements": null,
  "SVGFEGaussianBlurElement.ariaErrorMessageElements": null,
  "SVGFEGaussianBlurElement.ariaFlowToElements": null,
  "SVGFEGaussianBlurElement.ariaLabelledByElements": null,
  "SVGFEGaussianBlurElement.ariaOwnsElements": null,
  "SVGFEGaussianBlurElement.firstElementChild": null,
  "SVGFEGaussianBlurElement.lastElementChild": null,
  "SVGFEGaussianBlurElement.previousElementSibling": null,
  "SVGFEGaussianBlurElement.nextElementSibling": null,
  "SVGFEGaussianBlurElement.ownerSVGElement": null,
  "SVGFEGaussianBlurElement.viewportElement": null,
  "SVGFEImageElement.ownerDocument": null,
  "SVGFEImageElement.parentNode": null,
  "SVGFEImageElement.parentElement": null,
  "SVGFEImageElement.childNodes": null,
  "SVGFEImageElement.firstChild": null,
  "SVGFEImageElement.lastChild": null,
  "SVGFEImageElement.previousSibling": null,
  "SVGFEImageElement.nextSibling": null,
  "SVGFEImageElement.attributes": null,
  "SVGFEImageElement.shadowRoot": null,
  "SVGFEImageElement.assignedSlot": "slot",
  "SVGFEImageElement.customElementRegistry": null,
  "SVGFEImageElement.ariaActiveDescendantElement": null,
  "SVGFEImageElement.ariaControlsElements": null,
  "SVGFEImageElement.ariaDescribedByElements": null,
  "SVGFEImageElement.ariaDetailsElements": null,
  "SVGFEImageElement.ariaErrorMessageElements": null,
  "SVGFEImageElement.ariaFlowToElements": null,
  "SVGFEImageElement.ariaLabelledByElements": null,
  "SVGFEImageElement.ariaOwnsElements": null,
  "SVGFEImageElement.firstElementChild": null,
  "SVGFEImageElement.lastElementChild": null,
  "SVGFEImageElement.previousElementSibling": null,
  "SVGFEImageElement.nextElementSibling": null,
  "SVGFEImageElement.ownerSVGElement": null,
  "SVGFEImageElement.viewportElement": null,
  "SVGFEMergeElement.ownerDocument": null,
  "SVGFEMergeElement.parentNode": null,
  "SVGFEMergeElement.parentElement": null,
  "SVGFEMergeElement.childNodes": null,
  "SVGFEMergeElement.firstChild": null,
  "SVGFEMergeElement.lastChild": null,
  "SVGFEMergeElement.previousSibling": null,
  "SVGFEMergeElement.nextSibling": null,
  "SVGFEMergeElement.attributes": null,
  "SVGFEMergeElement.shadowRoot": null,
  "SVGFEMergeElement.assignedSlot": "slot",
  "SVGFEMergeElement.customElementRegistry": null,
  "SVGFEMergeElement.ariaActiveDescendantElement": null,
  "SVGFEMergeElement.ariaControlsElements": null,
  "SVGFEMergeElement.ariaDescribedByElements": null,
  "SVGFEMergeElement.ariaDetailsElements": null,
  "SVGFEMergeElement.ariaErrorMessageElements": null,
  "SVGFEMergeElement.ariaFlowToElements": null,
  "SVGFEMergeElement.ariaLabelledByElements": null,
  "SVGFEMergeElement.ariaOwnsElements": null,
  "SVGFEMergeElement.firstElementChild": null,
  "SVGFEMergeElement.lastElementChild": null,
  "SVGFEMergeElement.previousElementSibling": null,
  "SVGFEMergeElement.nextElementSibling": null,
  "SVGFEMergeElement.ownerSVGElement": null,
  "SVGFEMergeElement.viewportElement": null,
  "SVGFEMergeNodeElement.ownerDocument": null,
  "SVGFEMergeNodeElement.parentNode": null,
  "SVGFEMergeNodeElement.parentElement": null,
  "SVGFEMergeNodeElement.childNodes": null,
  "SVGFEMergeNodeElement.firstChild": null,
  "SVGFEMergeNodeElement.lastChild": null,
  "SVGFEMergeNodeElement.previousSibling": null,
  "SVGFEMergeNodeElement.nextSibling": null,
  "SVGFEMergeNodeElement.attributes": null,
  "SVGFEMergeNodeElement.shadowRoot": null,
  "SVGFEMergeNodeElement.assignedSlot": "slot",
  "SVGFEMergeNodeElement.customElementRegistry": null,
  "SVGFEMergeNodeElement.ariaActiveDescendantElement": null,
  "SVGFEMergeNodeElement.ariaControlsElements": null,
  "SVGFEMergeNodeElement.ariaDescribedByElements": null,
  "SVGFEMergeNodeElement.ariaDetailsElements": null,
  "SVGFEMergeNodeElement.ariaErrorMessageElements": null,
  "SVGFEMergeNodeElement.ariaFlowToElements": null,
  "SVGFEMergeNodeElement.ariaLabelledByElements": null,
  "SVGFEMergeNodeElement.ariaOwnsElements": null,
  "SVGFEMergeNodeElement.firstElementChild": null,
  "SVGFEMergeNodeElement.lastElementChild": null,
  "SVGFEMergeNodeElement.previousElementSibling": null,
  "SVGFEMergeNodeElement.nextElementSibling": null,
  "SVGFEMergeNodeElement.ownerSVGElement": null,
  "SVGFEMergeNodeElement.viewportElement": null,
  "SVGFEMorphologyElement.ownerDocument": null,
  "SVGFEMorphologyElement.parentNode": null,
  "SVGFEMorphologyElement.parentElement": null,
  "SVGFEMorphologyElement.childNodes": null,
  "SVGFEMorphologyElement.firstChild": null,
  "SVGFEMorphologyElement.lastChild": null,
  "SVGFEMorphologyElement.previousSibling": null,
  "SVGFEMorphologyElement.nextSibling": null,
  "SVGFEMorphologyElement.attributes": null,
  "SVGFEMorphologyElement.shadowRoot": null,
  "SVGFEMorphologyElement.assignedSlot": "slot",
  "SVGFEMorphologyElement.customElementRegistry": null,
  "SVGFEMorphologyElement.ariaActiveDescendantElement": null,
  "SVGFEMorphologyElement.ariaControlsElements": null,
  "SVGFEMorphologyElement.ariaDescribedByElements": null,
  "SVGFEMorphologyElement.ariaDetailsElements": null,
  "SVGFEMorphologyElement.ariaErrorMessageElements": null,
  "SVGFEMorphologyElement.ariaFlowToElements": null,
  "SVGFEMorphologyElement.ariaLabelledByElements": null,
  "SVGFEMorphologyElement.ariaOwnsElements": null,
  "SVGFEMorphologyElement.firstElementChild": null,
  "SVGFEMorphologyElement.lastElementChild": null,
  "SVGFEMorphologyElement.previousElementSibling": null,
  "SVGFEMorphologyElement.nextElementSibling": null,
  "SVGFEMorphologyElement.ownerSVGElement": null,
  "SVGFEMorphologyElement.viewportElement": null,
  "SVGFEOffsetElement.ownerDocument": null,
  "SVGFEOffsetElement.parentNode": null,
  "SVGFEOffsetElement.parentElement": null,
  "SVGFEOffsetElement.childNodes": null,
  "SVGFEOffsetElement.firstChild": null,
  "SVGFEOffsetElement.lastChild": null,
  "SVGFEOffsetElement.previousSibling": null,
  "SVGFEOffsetElement.nextSibling": null,
  "SVGFEOffsetElement.attributes": null,
  "SVGFEOffsetElement.shadowRoot": null,
  "SVGFEOffsetElement.assignedSlot": "slot",
  "SVGFEOffsetElement.customElementRegistry": null,
  "SVGFEOffsetElement.ariaActiveDescendantElement": null,
  "SVGFEOffsetElement.ariaControlsElements": null,
  "SVGFEOffsetElement.ariaDescribedByElements": null,
  "SVGFEOffsetElement.ariaDetailsElements": null,
  "SVGFEOffsetElement.ariaErrorMessageElements": null,
  "SVGFEOffsetElement.ariaFlowToElements": null,
  "SVGFEOffsetElement.ariaLabelledByElements": null,
  "SVGFEOffsetElement.ariaOwnsElements": null,
  "SVGFEOffsetElement.firstElementChild": null,
  "SVGFEOffsetElement.lastElementChild": null,
  "SVGFEOffsetElement.previousElementSibling": null,
  "SVGFEOffsetElement.nextElementSibling": null,
  "SVGFEOffsetElement.ownerSVGElement": null,
  "SVGFEOffsetElement.viewportElement": null,
  "SVGFEPointLightElement.ownerDocument": null,
  "SVGFEPointLightElement.parentNode": null,
  "SVGFEPointLightElement.parentElement": null,
  "SVGFEPointLightElement.childNodes": null,
  "SVGFEPointLightElement.firstChild": null,
  "SVGFEPointLightElement.lastChild": null,
  "SVGFEPointLightElement.previousSibling": null,
  "SVGFEPointLightElement.nextSibling": null,
  "SVGFEPointLightElement.attributes": null,
  "SVGFEPointLightElement.shadowRoot": null,
  "SVGFEPointLightElement.assignedSlot": "slot",
  "SVGFEPointLightElement.customElementRegistry": null,
  "SVGFEPointLightElement.ariaActiveDescendantElement": null,
  "SVGFEPointLightElement.ariaControlsElements": null,
  "SVGFEPointLightElement.ariaDescribedByElements": null,
  "SVGFEPointLightElement.ariaDetailsElements": null,
  "SVGFEPointLightElement.ariaErrorMessageElements": null,
  "SVGFEPointLightElement.ariaFlowToElements": null,
  "SVGFEPointLightElement.ariaLabelledByElements": null,
  "SVGFEPointLightElement.ariaOwnsElements": null,
  "SVGFEPointLightElement.firstElementChild": null,
  "SVGFEPointLightElement.lastElementChild": null,
  "SVGFEPointLightElement.previousElementSibling": null,
  "SVGFEPointLightElement.nextElementSibling": null,
  "SVGFEPointLightElement.ownerSVGElement": null,
  "SVGFEPointLightElement.viewportElement": null,
  "SVGFESpecularLightingElement.ownerDocument": null,
  "SVGFESpecularLightingElement.parentNode": null,
  "SVGFESpecularLightingElement.parentElement": null,
  "SVGFESpecularLightingElement.childNodes": null,
  "SVGFESpecularLightingElement.firstChild": null,
  "SVGFESpecularLightingElement.lastChild": null,
  "SVGFESpecularLightingElement.previousSibling": null,
  "SVGFESpecularLightingElement.nextSibling": null,
  "SVGFESpecularLightingElement.attributes": null,
  "SVGFESpecularLightingElement.shadowRoot": null,
  "SVGFESpecularLightingElement.assignedSlot": "slot",
  "SVGFESpecularLightingElement.customElementRegistry": null,
  "SVGFESpecularLightingElement.ariaActiveDescendantElement": null,
  "SVGFESpecularLightingElement.ariaControlsElements": null,
  "SVGFESpecularLightingElement.ariaDescribedByElements": null,
  "SVGFESpecularLightingElement.ariaDetailsElements": null,
  "SVGFESpecularLightingElement.ariaErrorMessageElements": null,
  "SVGFESpecularLightingElement.ariaFlowToElements": null,
  "SVGFESpecularLightingElement.ariaLabelledByElements": null,
  "SVGFESpecularLightingElement.ariaOwnsElements": null,
  "SVGFESpecularLightingElement.firstElementChild": null,
  "SVGFESpecularLightingElement.lastElementChild": null,
  "SVGFESpecularLightingElement.previousElementSibling": null,
  "SVGFESpecularLightingElement.nextElementSibling": null,
  "SVGFESpecularLightingElement.ownerSVGElement": null,
  "SVGFESpecularLightingElement.viewportElement": null,
  "SVGFESpotLightElement.ownerDocument": null,
  "SVGFESpotLightElement.parentNode": null,
  "SVGFESpotLightElement.parentElement": null,
  "SVGFESpotLightElement.childNodes": null,
  "SVGFESpotLightElement.firstChild": null,
  "SVGFESpotLightElement.lastChild": null,
  "SVGFESpotLightElement.previousSibling": null,
  "SVGFESpotLightElement.nextSibling": null,
  "SVGFESpotLightElement.attributes": null,
  "SVGFESpotLightElement.shadowRoot": null,
  "SVGFESpotLightElement.assignedSlot": "slot",
  "SVGFESpotLightElement.customElementRegistry": null,
  "SVGFESpotLightElement.ariaActiveDescendantElement": null,
  "SVGFESpotLightElement.ariaControlsElements": null,
  "SVGFESpotLightElement.ariaDescribedByElements": null,
  "SVGFESpotLightElement.ariaDetailsElements": null,
  "SVGFESpotLightElement.ariaErrorMessageElements": null,
  "SVGFESpotLightElement.ariaFlowToElements": null,
  "SVGFESpotLightElement.ariaLabelledByElements": null,
  "SVGFESpotLightElement.ariaOwnsElements": null,
  "SVGFESpotLightElement.firstElementChild": null,
  "SVGFESpotLightElement.lastElementChild": null,
  "SVGFESpotLightElement.previousElementSibling": null,
  "SVGFESpotLightElement.nextElementSibling": null,
  "SVGFESpotLightElement.ownerSVGElement": null,
  "SVGFESpotLightElement.viewportElement": null,
  "SVGFETileElement.ownerDocument": null,
  "SVGFETileElement.parentNode": null,
  "SVGFETileElement.parentElement": null,
  "SVGFETileElement.childNodes": null,
  "SVGFETileElement.firstChild": null,
  "SVGFETileElement.lastChild": null,
  "SVGFETileElement.previousSibling": null,
  "SVGFETileElement.nextSibling": null,
  "SVGFETileElement.attributes": null,
  "SVGFETileElement.shadowRoot": null,
  "SVGFETileElement.assignedSlot": "slot",
  "SVGFETileElement.customElementRegistry": null,
  "SVGFETileElement.ariaActiveDescendantElement": null,
  "SVGFETileElement.ariaControlsElements": null,
  "SVGFETileElement.ariaDescribedByElements": null,
  "SVGFETileElement.ariaDetailsElements": null,
  "SVGFETileElement.ariaErrorMessageElements": null,
  "SVGFETileElement.ariaFlowToElements": null,
  "SVGFETileElement.ariaLabelledByElements": null,
  "SVGFETileElement.ariaOwnsElements": null,
  "SVGFETileElement.firstElementChild": null,
  "SVGFETileElement.lastElementChild": null,
  "SVGFETileElement.previousElementSibling": null,
  "SVGFETileElement.nextElementSibling": null,
  "SVGFETileElement.ownerSVGElement": null,
  "SVGFETileElement.viewportElement": null,
  "SVGFETurbulenceElement.ownerDocument": null,
  "SVGFETurbulenceElement.parentNode": null,
  "SVGFETurbulenceElement.parentElement": null,
  "SVGFETurbulenceElement.childNodes": null,
  "SVGFETurbulenceElement.firstChild": null,
  "SVGFETurbulenceElement.lastChild": null,
  "SVGFETurbulenceElement.previousSibling": null,
  "SVGFETurbulenceElement.nextSibling": null,
  "SVGFETurbulenceElement.attributes": null,
  "SVGFETurbulenceElement.shadowRoot": null,
  "SVGFETurbulenceElement.assignedSlot": "slot",
  "SVGFETurbulenceElement.customElementRegistry": null,
  "SVGFETurbulenceElement.ariaActiveDescendantElement": null,
  "SVGFETurbulenceElement.ariaControlsElements": null,
  "SVGFETurbulenceElement.ariaDescribedByElements": null,
  "SVGFETurbulenceElement.ariaDetailsElements": null,
  "SVGFETurbulenceElement.ariaErrorMessageElements": null,
  "SVGFETurbulenceElement.ariaFlowToElements": null,
  "SVGFETurbulenceElement.ariaLabelledByElements": null,
  "SVGFETurbulenceElement.ariaOwnsElements": null,
  "SVGFETurbulenceElement.firstElementChild": null,
  "SVGFETurbulenceElement.lastElementChild": null,
  "SVGFETurbulenceElement.previousElementSibling": null,
  "SVGFETurbulenceElement.nextElementSibling": null,
  "SVGFETurbulenceElement.ownerSVGElement": null,
  "SVGFETurbulenceElement.viewportElement": null,
  "SVGFilterElement.ownerDocument": null,
  "SVGFilterElement.parentNode": null,
  "SVGFilterElement.parentElement": null,
  "SVGFilterElement.childNodes": null,
  "SVGFilterElement.firstChild": null,
  "SVGFilterElement.lastChild": null,
  "SVGFilterElement.previousSibling": null,
  "SVGFilterElement.nextSibling": null,
  "SVGFilterElement.attributes": null,
  "SVGFilterElement.shadowRoot": null,
  "SVGFilterElement.assignedSlot": "slot",
  "SVGFilterElement.customElementRegistry": null,
  "SVGFilterElement.ariaActiveDescendantElement": null,
  "SVGFilterElement.ariaControlsElements": null,
  "SVGFilterElement.ariaDescribedByElements": null,
  "SVGFilterElement.ariaDetailsElements": null,
  "SVGFilterElement.ariaErrorMessageElements": null,
  "SVGFilterElement.ariaFlowToElements": null,
  "SVGFilterElement.ariaLabelledByElements": null,
  "SVGFilterElement.ariaOwnsElements": null,
  "SVGFilterElement.firstElementChild": null,
  "SVGFilterElement.lastElementChild": null,
  "SVGFilterElement.previousElementSibling": null,
  "SVGFilterElement.nextElementSibling": null,
  "SVGFilterElement.ownerSVGElement": null,
  "SVGFilterElement.viewportElement": null,
  "SVGForeignObjectElement.ownerDocument": null,
  "SVGForeignObjectElement.parentNode": null,
  "SVGForeignObjectElement.parentElement": null,
  "SVGForeignObjectElement.childNodes": null,
  "SVGForeignObjectElement.firstChild": null,
  "SVGForeignObjectElement.lastChild": null,
  "SVGForeignObjectElement.previousSibling": null,
  "SVGForeignObjectElement.nextSibling": null,
  "SVGForeignObjectElement.attributes": null,
  "SVGForeignObjectElement.shadowRoot": null,
  "SVGForeignObjectElement.assignedSlot": "slot",
  "SVGForeignObjectElement.customElementRegistry": null,
  "SVGForeignObjectElement.ariaActiveDescendantElement": null,
  "SVGForeignObjectElement.ariaControlsElements": null,
  "SVGForeignObjectElement.ariaDescribedByElements": null,
  "SVGForeignObjectElement.ariaDetailsElements": null,
  "SVGForeignObjectElement.ariaErrorMessageElements": null,
  "SVGForeignObjectElement.ariaFlowToElements": null,
  "SVGForeignObjectElement.ariaLabelledByElements": null,
  "SVGForeignObjectElement.ariaOwnsElements": null,
  "SVGForeignObjectElement.firstElementChild": null,
  "SVGForeignObjectElement.lastElementChild": null,
  "SVGForeignObjectElement.previousElementSibling": null,
  "SVGForeignObjectElement.nextElementSibling": null,
  "SVGForeignObjectElement.ownerSVGElement": null,
  "SVGForeignObjectElement.viewportElement": null,
  "SVGForeignObjectElement.nearestViewportElement": null,
  "SVGForeignObjectElement.farthestViewportElement": null,
  "SVGGeometryElement.ownerDocument": null,
  "SVGGeometryElement.parentNode": null,
  "SVGGeometryElement.parentElement": null,
  "SVGGeometryElement.childNodes": null,
  "SVGGeometryElement.firstChild": null,
  "SVGGeometryElement.lastChild": null,
  "SVGGeometryElement.previousSibling": null,
  "SVGGeometryElement.nextSibling": null,
  "SVGGeometryElement.attributes": null,
  "SVGGeometryElement.shadowRoot": null,
  "SVGGeometryElement.assignedSlot": "slot",
  "SVGGeometryElement.customElementRegistry": null,
  "SVGGeometryElement.ariaActiveDescendantElement": null,
  "SVGGeometryElement.ariaControlsElements": null,
  "SVGGeometryElement.ariaDescribedByElements": null,
  "SVGGeometryElement.ariaDetailsElements": null,
  "SVGGeometryElement.ariaErrorMessageElements": null,
  "SVGGeometryElement.ariaFlowToElements": null,
  "SVGGeometryElement.ariaLabelledByElements": null,
  "SVGGeometryElement.ariaOwnsElements": null,
  "SVGGeometryElement.firstElementChild": null,
  "SVGGeometryElement.lastElementChild": null,
  "SVGGeometryElement.previousElementSibling": null,
  "SVGGeometryElement.nextElementSibling": null,
  "SVGGeometryElement.ownerSVGElement": null,
  "SVGGeometryElement.viewportElement": null,
  "SVGGeometryElement.nearestViewportElement": null,
  "SVGGeometryElement.farthestViewportElement": null,
  "SVGGradientElement.ownerDocument": null,
  "SVGGradientElement.parentNode": null,
  "SVGGradientElement.parentElement": null,
  "SVGGradientElement.childNodes": null,
  "SVGGradientElement.firstChild": null,
  "SVGGradientElement.lastChild": null,
  "SVGGradientElement.previousSibling": null,
  "SVGGradientElement.nextSibling": null,
  "SVGGradientElement.attributes": null,
  "SVGGradientElement.shadowRoot": null,
  "SVGGradientElement.assignedSlot": "slot",
  "SVGGradientElement.customElementRegistry": null,
  "SVGGradientElement.ariaActiveDescendantElement": null,
  "SVGGradientElement.ariaControlsElements": null,
  "SVGGradientElement.ariaDescribedByElements": null,
  "SVGGradientElement.ariaDetailsElements": null,
  "SVGGradientElement.ariaErrorMessageElements": null,
  "SVGGradientElement.ariaFlowToElements": null,
  "SVGGradientElement.ariaLabelledByElements": null,
  "SVGGradientElement.ariaOwnsElements": null,
  "SVGGradientElement.firstElementChild": null,
  "SVGGradientElement.lastElementChild": null,
  "SVGGradientElement.previousElementSibling": null,
  "SVGGradientElement.nextElementSibling": null,
  "SVGGradientElement.ownerSVGElement": null,
  "SVGGradientElement.viewportElement": null,
  "SVGGraphicsElement.ownerDocument": null,
  "SVGGraphicsElement.parentNode": null,
  "SVGGraphicsElement.parentElement": null,
  "SVGGraphicsElement.childNodes": null,
  "SVGGraphicsElement.firstChild": null,
  "SVGGraphicsElement.lastChild": null,
  "SVGGraphicsElement.previousSibling": null,
  "SVGGraphicsElement.nextSibling": null,
  "SVGGraphicsElement.attributes": null,
  "SVGGraphicsElement.shadowRoot": null,
  "SVGGraphicsElement.assignedSlot": "slot",
  "SVGGraphicsElement.customElementRegistry": null,
  "SVGGraphicsElement.ariaActiveDescendantElement": null,
  "SVGGraphicsElement.ariaControlsElements": null,
  "SVGGraphicsElement.ariaDescribedByElements": null,
  "SVGGraphicsElement.ariaDetailsElements": null,
  "SVGGraphicsElement.ariaErrorMessageElements": null,
  "SVGGraphicsElement.ariaFlowToElements": null,
  "SVGGraphicsElement.ariaLabelledByElements": null,
  "SVGGraphicsElement.ariaOwnsElements": null,
  "SVGGraphicsElement.firstElementChild": null,
  "SVGGraphicsElement.lastElementChild": null,
  "SVGGraphicsElement.previousElementSibling": null,
  "SVGGraphicsElement.nextElementSibling": null,
  "SVGGraphicsElement.ownerSVGElement": null,
  "SVGGraphicsElement.viewportElement": null,
  "SVGGraphicsElement.nearestViewportElement": null,
  "SVGGraphicsElement.farthestViewportElement": null,
  "SVGGElement.ownerDocument": null,
  "SVGGElement.parentNode": null,
  "SVGGElement.parentElement": null,
  "SVGGElement.childNodes": null,
  "SVGGElement.firstChild": null,
  "SVGGElement.lastChild": null,
  "SVGGElement.previousSibling": null,
  "SVGGElement.nextSibling": null,
  "SVGGElement.attributes": null,
  "SVGGElement.shadowRoot": null,
  "SVGGElement.assignedSlot": "slot",
  "SVGGElement.customElementRegistry": null,
  "SVGGElement.ariaActiveDescendantElement": null,
  "SVGGElement.ariaControlsElements": null,
  "SVGGElement.ariaDescribedByElements": null,
  "SVGGElement.ariaDetailsElements": null,
  "SVGGElement.ariaErrorMessageElements": null,
  "SVGGElement.ariaFlowToElements": null,
  "SVGGElement.ariaLabelledByElements": null,
  "SVGGElement.ariaOwnsElements": null,
  "SVGGElement.firstElementChild": null,
  "SVGGElement.lastElementChild": null,
  "SVGGElement.previousElementSibling": null,
  "SVGGElement.nextElementSibling": null,
  "SVGGElement.ownerSVGElement": null,
  "SVGGElement.viewportElement": null,
  "SVGGElement.nearestViewportElement": null,
  "SVGGElement.farthestViewportElement": null,
  "SVGImageElement.ownerDocument": null,
  "SVGImageElement.parentNode": null,
  "SVGImageElement.parentElement": null,
  "SVGImageElement.childNodes": null,
  "SVGImageElement.firstChild": null,
  "SVGImageElement.lastChild": null,
  "SVGImageElement.previousSibling": null,
  "SVGImageElement.nextSibling": null,
  "SVGImageElement.attributes": null,
  "SVGImageElement.shadowRoot": null,
  "SVGImageElement.assignedSlot": "slot",
  "SVGImageElement.customElementRegistry": null,
  "SVGImageElement.ariaActiveDescendantElement": null,
  "SVGImageElement.ariaControlsElements": null,
  "SVGImageElement.ariaDescribedByElements": null,
  "SVGImageElement.ariaDetailsElements": null,
  "SVGImageElement.ariaErrorMessageElements": null,
  "SVGImageElement.ariaFlowToElements": null,
  "SVGImageElement.ariaLabelledByElements": null,
  "SVGImageElement.ariaOwnsElements": null,
  "SVGImageElement.firstElementChild": null,
  "SVGImageElement.lastElementChild": null,
  "SVGImageElement.previousElementSibling": null,
  "SVGImageElement.nextElementSibling": null,
  "SVGImageElement.ownerSVGElement": null,
  "SVGImageElement.viewportElement": null,
  "SVGImageElement.nearestViewportElement": null,
  "SVGImageElement.farthestViewportElement": null,
  "SVGLinearGradientElement.ownerDocument": null,
  "SVGLinearGradientElement.parentNode": null,
  "SVGLinearGradientElement.parentElement": null,
  "SVGLinearGradientElement.childNodes": null,
  "SVGLinearGradientElement.firstChild": null,
  "SVGLinearGradientElement.lastChild": null,
  "SVGLinearGradientElement.previousSibling": null,
  "SVGLinearGradientElement.nextSibling": null,
  "SVGLinearGradientElement.attributes": null,
  "SVGLinearGradientElement.shadowRoot": null,
  "SVGLinearGradientElement.assignedSlot": "slot",
  "SVGLinearGradientElement.customElementRegistry": null,
  "SVGLinearGradientElement.ariaActiveDescendantElement": null,
  "SVGLinearGradientElement.ariaControlsElements": null,
  "SVGLinearGradientElement.ariaDescribedByElements": null,
  "SVGLinearGradientElement.ariaDetailsElements": null,
  "SVGLinearGradientElement.ariaErrorMessageElements": null,
  "SVGLinearGradientElement.ariaFlowToElements": null,
  "SVGLinearGradientElement.ariaLabelledByElements": null,
  "SVGLinearGradientElement.ariaOwnsElements": null,
  "SVGLinearGradientElement.firstElementChild": null,
  "SVGLinearGradientElement.lastElementChild": null,
  "SVGLinearGradientElement.previousElementSibling": null,
  "SVGLinearGradientElement.nextElementSibling": null,
  "SVGLinearGradientElement.ownerSVGElement": null,
  "SVGLinearGradientElement.viewportElement": null,
  "SVGLineElement.ownerDocument": null,
  "SVGLineElement.parentNode": null,
  "SVGLineElement.parentElement": null,
  "SVGLineElement.childNodes": null,
  "SVGLineElement.firstChild": null,
  "SVGLineElement.lastChild": null,
  "SVGLineElement.previousSibling": null,
  "SVGLineElement.nextSibling": null,
  "SVGLineElement.attributes": null,
  "SVGLineElement.shadowRoot": null,
  "SVGLineElement.assignedSlot": "slot",
  "SVGLineElement.customElementRegistry": null,
  "SVGLineElement.ariaActiveDescendantElement": null,
  "SVGLineElement.ariaControlsElements": null,
  "SVGLineElement.ariaDescribedByElements": null,
  "SVGLineElement.ariaDetailsElements": null,
  "SVGLineElement.ariaErrorMessageElements": null,
  "SVGLineElement.ariaFlowToElements": null,
  "SVGLineElement.ariaLabelledByElements": null,
  "SVGLineElement.ariaOwnsElements": null,
  "SVGLineElement.firstElementChild": null,
  "SVGLineElement.lastElementChild": null,
  "SVGLineElement.previousElementSibling": null,
  "SVGLineElement.nextElementSibling": null,
  "SVGLineElement.ownerSVGElement": null,
  "SVGLineElement.viewportElement": null,
  "SVGLineElement.nearestViewportElement": null,
  "SVGLineElement.farthestViewportElement": null,
  "SVGMarkerElement.ownerDocument": null,
  "SVGMarkerElement.parentNode": null,
  "SVGMarkerElement.parentElement": null,
  "SVGMarkerElement.childNodes": null,
  "SVGMarkerElement.firstChild": null,
  "SVGMarkerElement.lastChild": null,
  "SVGMarkerElement.previousSibling": null,
  "SVGMarkerElement.nextSibling": null,
  "SVGMarkerElement.attributes": null,
  "SVGMarkerElement.shadowRoot": null,
  "SVGMarkerElement.assignedSlot": "slot",
  "SVGMarkerElement.customElementRegistry": null,
  "SVGMarkerElement.ariaActiveDescendantElement": null,
  "SVGMarkerElement.ariaControlsElements": null,
  "SVGMarkerElement.ariaDescribedByElements": null,
  "SVGMarkerElement.ariaDetailsElements": null,
  "SVGMarkerElement.ariaErrorMessageElements": null,
  "SVGMarkerElement.ariaFlowToElements": null,
  "SVGMarkerElement.ariaLabelledByElements": null,
  "SVGMarkerElement.ariaOwnsElements": null,
  "SVGMarkerElement.firstElementChild": null,
  "SVGMarkerElement.lastElementChild": null,
  "SVGMarkerElement.previousElementSibling": null,
  "SVGMarkerElement.nextElementSibling": null,
  "SVGMarkerElement.ownerSVGElement": null,
  "SVGMarkerElement.viewportElement": null,
  "SVGMaskElement.ownerDocument": null,
  "SVGMaskElement.parentNode": null,
  "SVGMaskElement.parentElement": null,
  "SVGMaskElement.childNodes": null,
  "SVGMaskElement.firstChild": null,
  "SVGMaskElement.lastChild": null,
  "SVGMaskElement.previousSibling": null,
  "SVGMaskElement.nextSibling": null,
  "SVGMaskElement.attributes": null,
  "SVGMaskElement.shadowRoot": null,
  "SVGMaskElement.assignedSlot": "slot",
  "SVGMaskElement.customElementRegistry": null,
  "SVGMaskElement.ariaActiveDescendantElement": null,
  "SVGMaskElement.ariaControlsElements": null,
  "SVGMaskElement.ariaDescribedByElements": null,
  "SVGMaskElement.ariaDetailsElements": null,
  "SVGMaskElement.ariaErrorMessageElements": null,
  "SVGMaskElement.ariaFlowToElements": null,
  "SVGMaskElement.ariaLabelledByElements": null,
  "SVGMaskElement.ariaOwnsElements": null,
  "SVGMaskElement.firstElementChild": null,
  "SVGMaskElement.lastElementChild": null,
  "SVGMaskElement.previousElementSibling": null,
  "SVGMaskElement.nextElementSibling": null,
  "SVGMaskElement.ownerSVGElement": null,
  "SVGMaskElement.viewportElement": null,
  "SVGMetadataElement.ownerDocument": null,
  "SVGMetadataElement.parentNode": null,
  "SVGMetadataElement.parentElement": null,
  "SVGMetadataElement.childNodes": null,
  "SVGMetadataElement.firstChild": null,
  "SVGMetadataElement.lastChild": null,
  "SVGMetadataElement.previousSibling": null,
  "SVGMetadataElement.nextSibling": null,
  "SVGMetadataElement.attributes": null,
  "SVGMetadataElement.shadowRoot": null,
  "SVGMetadataElement.assignedSlot": "slot",
  "SVGMetadataElement.customElementRegistry": null,
  "SVGMetadataElement.ariaActiveDescendantElement": null,
  "SVGMetadataElement.ariaControlsElements": null,
  "SVGMetadataElement.ariaDescribedByElements": null,
  "SVGMetadataElement.ariaDetailsElements": null,
  "SVGMetadataElement.ariaErrorMessageElements": null,
  "SVGMetadataElement.ariaFlowToElements": null,
  "SVGMetadataElement.ariaLabelledByElements": null,
  "SVGMetadataElement.ariaOwnsElements": null,
  "SVGMetadataElement.firstElementChild": null,
  "SVGMetadataElement.lastElementChild": null,
  "SVGMetadataElement.previousElementSibling": null,
  "SVGMetadataElement.nextElementSibling": null,
  "SVGMetadataElement.ownerSVGElement": null,
  "SVGMetadataElement.viewportElement": null,
  "SVGMPathElement.ownerDocument": null,
  "SVGMPathElement.parentNode": null,
  "SVGMPathElement.parentElement": null,
  "SVGMPathElement.childNodes": null,
  "SVGMPathElement.firstChild": null,
  "SVGMPathElement.lastChild": null,
  "SVGMPathElement.previousSibling": null,
  "SVGMPathElement.nextSibling": null,
  "SVGMPathElement.attributes": null,
  "SVGMPathElement.shadowRoot": null,
  "SVGMPathElement.assignedSlot": "slot",
  "SVGMPathElement.customElementRegistry": null,
  "SVGMPathElement.ariaActiveDescendantElement": null,
  "SVGMPathElement.ariaControlsElements": null,
  "SVGMPathElement.ariaDescribedByElements": null,
  "SVGMPathElement.ariaDetailsElements": null,
  "SVGMPathElement.ariaErrorMessageElements": null,
  "SVGMPathElement.ariaFlowToElements": null,
  "SVGMPathElement.ariaLabelledByElements": null,
  "SVGMPathElement.ariaOwnsElements": null,
  "SVGMPathElement.firstElementChild": null,
  "SVGMPathElement.lastElementChild": null,
  "SVGMPathElement.previousElementSibling": null,
  "SVGMPathElement.nextElementSibling": null,
  "SVGMPathElement.ownerSVGElement": null,
  "SVGMPathElement.viewportElement": null,
  "SVGPathElement.ownerDocument": null,
  "SVGPathElement.parentNode": null,
  "SVGPathElement.parentElement": null,
  "SVGPathElement.childNodes": null,
  "SVGPathElement.firstChild": null,
  "SVGPathElement.lastChild": null,
  "SVGPathElement.previousSibling": null,
  "SVGPathElement.nextSibling": null,
  "SVGPathElement.attributes": null,
  "SVGPathElement.shadowRoot": null,
  "SVGPathElement.assignedSlot": "slot",
  "SVGPathElement.customElementRegistry": null,
  "SVGPathElement.ariaActiveDescendantElement": null,
  "SVGPathElement.ariaControlsElements": null,
  "SVGPathElement.ariaDescribedByElements": null,
  "SVGPathElement.ariaDetailsElements": null,
  "SVGPathElement.ariaErrorMessageElements": null,
  "SVGPathElement.ariaFlowToElements": null,
  "SVGPathElement.ariaLabelledByElements": null,
  "SVGPathElement.ariaOwnsElements": null,
  "SVGPathElement.firstElementChild": null,
  "SVGPathElement.lastElementChild": null,
  "SVGPathElement.previousElementSibling": null,
  "SVGPathElement.nextElementSibling": null,
  "SVGPathElement.ownerSVGElement": null,
  "SVGPathElement.viewportElement": null,
  "SVGPathElement.nearestViewportElement": null,
  "SVGPathElement.farthestViewportElement": null,
  "SVGPatternElement.ownerDocument": null,
  "SVGPatternElement.parentNode": null,
  "SVGPatternElement.parentElement": null,
  "SVGPatternElement.childNodes": null,
  "SVGPatternElement.firstChild": null,
  "SVGPatternElement.lastChild": null,
  "SVGPatternElement.previousSibling": null,
  "SVGPatternElement.nextSibling": null,
  "SVGPatternElement.attributes": null,
  "SVGPatternElement.shadowRoot": null,
  "SVGPatternElement.assignedSlot": "slot",
  "SVGPatternElement.customElementRegistry": null,
  "SVGPatternElement.ariaActiveDescendantElement": null,
  "SVGPatternElement.ariaControlsElements": null,
  "SVGPatternElement.ariaDescribedByElements": null,
  "SVGPatternElement.ariaDetailsElements": null,
  "SVGPatternElement.ariaErrorMessageElements": null,
  "SVGPatternElement.ariaFlowToElements": null,
  "SVGPatternElement.ariaLabelledByElements": null,
  "SVGPatternElement.ariaOwnsElements": null,
  "SVGPatternElement.firstElementChild": null,
  "SVGPatternElement.lastElementChild": null,
  "SVGPatternElement.previousElementSibling": null,
  "SVGPatternElement.nextElementSibling": null,
  "SVGPatternElement.ownerSVGElement": null,
  "SVGPatternElement.viewportElement": null,
  "SVGPolygonElement.ownerDocument": null,
  "SVGPolygonElement.parentNode": null,
  "SVGPolygonElement.parentElement": null,
  "SVGPolygonElement.childNodes": null,
  "SVGPolygonElement.firstChild": null,
  "SVGPolygonElement.lastChild": null,
  "SVGPolygonElement.previousSibling": null,
  "SVGPolygonElement.nextSibling": null,
  "SVGPolygonElement.attributes": null,
  "SVGPolygonElement.shadowRoot": null,
  "SVGPolygonElement.assignedSlot": "slot",
  "SVGPolygonElement.customElementRegistry": null,
  "SVGPolygonElement.ariaActiveDescendantElement": null,
  "SVGPolygonElement.ariaControlsElements": null,
  "SVGPolygonElement.ariaDescribedByElements": null,
  "SVGPolygonElement.ariaDetailsElements": null,
  "SVGPolygonElement.ariaErrorMessageElements": null,
  "SVGPolygonElement.ariaFlowToElements": null,
  "SVGPolygonElement.ariaLabelledByElements": null,
  "SVGPolygonElement.ariaOwnsElements": null,
  "SVGPolygonElement.firstElementChild": null,
  "SVGPolygonElement.lastElementChild": null,
  "SVGPolygonElement.previousElementSibling": null,
  "SVGPolygonElement.nextElementSibling": null,
  "SVGPolygonElement.ownerSVGElement": null,
  "SVGPolygonElement.viewportElement": null,
  "SVGPolygonElement.nearestViewportElement": null,
  "SVGPolygonElement.farthestViewportElement": null,
  "SVGPolylineElement.ownerDocument": null,
  "SVGPolylineElement.parentNode": null,
  "SVGPolylineElement.parentElement": null,
  "SVGPolylineElement.childNodes": null,
  "SVGPolylineElement.firstChild": null,
  "SVGPolylineElement.lastChild": null,
  "SVGPolylineElement.previousSibling": null,
  "SVGPolylineElement.nextSibling": null,
  "SVGPolylineElement.attributes": null,
  "SVGPolylineElement.shadowRoot": null,
  "SVGPolylineElement.assignedSlot": "slot",
  "SVGPolylineElement.customElementRegistry": null,
  "SVGPolylineElement.ariaActiveDescendantElement": null,
  "SVGPolylineElement.ariaControlsElements": null,
  "SVGPolylineElement.ariaDescribedByElements": null,
  "SVGPolylineElement.ariaDetailsElements": null,
  "SVGPolylineElement.ariaErrorMessageElements": null,
  "SVGPolylineElement.ariaFlowToElements": null,
  "SVGPolylineElement.ariaLabelledByElements": null,
  "SVGPolylineElement.ariaOwnsElements": null,
  "SVGPolylineElement.firstElementChild": null,
  "SVGPolylineElement.lastElementChild": null,
  "SVGPolylineElement.previousElementSibling": null,
  "SVGPolylineElement.nextElementSibling": null,
  "SVGPolylineElement.ownerSVGElement": null,
  "SVGPolylineElement.viewportElement": null,
  "SVGPolylineElement.nearestViewportElement": null,
  "SVGPolylineElement.farthestViewportElement": null,
  "SVGRadialGradientElement.ownerDocument": null,
  "SVGRadialGradientElement.parentNode": null,
  "SVGRadialGradientElement.parentElement": null,
  "SVGRadialGradientElement.childNodes": null,
  "SVGRadialGradientElement.firstChild": null,
  "SVGRadialGradientElement.lastChild": null,
  "SVGRadialGradientElement.previousSibling": null,
  "SVGRadialGradientElement.nextSibling": null,
  "SVGRadialGradientElement.attributes": null,
  "SVGRadialGradientElement.shadowRoot": null,
  "SVGRadialGradientElement.assignedSlot": "slot",
  "SVGRadialGradientElement.customElementRegistry": null,
  "SVGRadialGradientElement.ariaActiveDescendantElement": null,
  "SVGRadialGradientElement.ariaControlsElements": null,
  "SVGRadialGradientElement.ariaDescribedByElements": null,
  "SVGRadialGradientElement.ariaDetailsElements": null,
  "SVGRadialGradientElement.ariaErrorMessageElements": null,
  "SVGRadialGradientElement.ariaFlowToElements": null,
  "SVGRadialGradientElement.ariaLabelledByElements": null,
  "SVGRadialGradientElement.ariaOwnsElements": null,
  "SVGRadialGradientElement.firstElementChild": null,
  "SVGRadialGradientElement.lastElementChild": null,
  "SVGRadialGradientElement.previousElementSibling": null,
  "SVGRadialGradientElement.nextElementSibling": null,
  "SVGRadialGradientElement.ownerSVGElement": null,
  "SVGRadialGradientElement.viewportElement": null,
  "SVGRectElement.ownerDocument": null,
  "SVGRectElement.parentNode": null,
  "SVGRectElement.parentElement": null,
  "SVGRectElement.childNodes": null,
  "SVGRectElement.firstChild": null,
  "SVGRectElement.lastChild": null,
  "SVGRectElement.previousSibling": null,
  "SVGRectElement.nextSibling": null,
  "SVGRectElement.attributes": null,
  "SVGRectElement.shadowRoot": null,
  "SVGRectElement.assignedSlot": "slot",
  "SVGRectElement.customElementRegistry": null,
  "SVGRectElement.ariaActiveDescendantElement": null,
  "SVGRectElement.ariaControlsElements": null,
  "SVGRectElement.ariaDescribedByElements": null,
  "SVGRectElement.ariaDetailsElements": null,
  "SVGRectElement.ariaErrorMessageElements": null,
  "SVGRectElement.ariaFlowToElements": null,
  "SVGRectElement.ariaLabelledByElements": null,
  "SVGRectElement.ariaOwnsElements": null,
  "SVGRectElement.firstElementChild": null,
  "SVGRectElement.lastElementChild": null,
  "SVGRectElement.previousElementSibling": null,
  "SVGRectElement.nextElementSibling": null,
  "SVGRectElement.ownerSVGElement": null,
  "SVGRectElement.viewportElement": null,
  "SVGRectElement.nearestViewportElement": null,
  "SVGRectElement.farthestViewportElement": null,
  "SVGScriptElement.ownerDocument": null,
  "SVGScriptElement.parentNode": null,
  "SVGScriptElement.parentElement": null,
  "SVGScriptElement.childNodes": null,
  "SVGScriptElement.firstChild": null,
  "SVGScriptElement.lastChild": null,
  "SVGScriptElement.previousSibling": null,
  "SVGScriptElement.nextSibling": null,
  "SVGScriptElement.attributes": null,
  "SVGScriptElement.shadowRoot": null,
  "SVGScriptElement.assignedSlot": "slot",
  "SVGScriptElement.customElementRegistry": null,
  "SVGScriptElement.ariaActiveDescendantElement": null,
  "SVGScriptElement.ariaControlsElements": null,
  "SVGScriptElement.ariaDescribedByElements": null,
  "SVGScriptElement.ariaDetailsElements": null,
  "SVGScriptElement.ariaErrorMessageElements": null,
  "SVGScriptElement.ariaFlowToElements": null,
  "SVGScriptElement.ariaLabelledByElements": null,
  "SVGScriptElement.ariaOwnsElements": null,
  "SVGScriptElement.firstElementChild": null,
  "SVGScriptElement.lastElementChild": null,
  "SVGScriptElement.previousElementSibling": null,
  "SVGScriptElement.nextElementSibling": null,
  "SVGScriptElement.ownerSVGElement": null,
  "SVGScriptElement.viewportElement": null,
  "SVGSetElement.ownerDocument": null,
  "SVGSetElement.parentNode": null,
  "SVGSetElement.parentElement": null,
  "SVGSetElement.childNodes": null,
  "SVGSetElement.firstChild": null,
  "SVGSetElement.lastChild": null,
  "SVGSetElement.previousSibling": null,
  "SVGSetElement.nextSibling": null,
  "SVGSetElement.attributes": null,
  "SVGSetElement.shadowRoot": null,
  "SVGSetElement.assignedSlot": "slot",
  "SVGSetElement.customElementRegistry": null,
  "SVGSetElement.ariaActiveDescendantElement": null,
  "SVGSetElement.ariaControlsElements": null,
  "SVGSetElement.ariaDescribedByElements": null,
  "SVGSetElement.ariaDetailsElements": null,
  "SVGSetElement.ariaErrorMessageElements": null,
  "SVGSetElement.ariaFlowToElements": null,
  "SVGSetElement.ariaLabelledByElements": null,
  "SVGSetElement.ariaOwnsElements": null,
  "SVGSetElement.firstElementChild": null,
  "SVGSetElement.lastElementChild": null,
  "SVGSetElement.previousElementSibling": null,
  "SVGSetElement.nextElementSibling": null,
  "SVGSetElement.ownerSVGElement": null,
  "SVGSetElement.viewportElement": null,
  "SVGSetElement.targetElement": null,
  "SVGStopElement.ownerDocument": null,
  "SVGStopElement.parentNode": null,
  "SVGStopElement.parentElement": null,
  "SVGStopElement.childNodes": null,
  "SVGStopElement.firstChild": null,
  "SVGStopElement.lastChild": null,
  "SVGStopElement.previousSibling": null,
  "SVGStopElement.nextSibling": null,
  "SVGStopElement.attributes": null,
  "SVGStopElement.shadowRoot": null,
  "SVGStopElement.assignedSlot": "slot",
  "SVGStopElement.customElementRegistry": null,
  "SVGStopElement.ariaActiveDescendantElement": null,
  "SVGStopElement.ariaControlsElements": null,
  "SVGStopElement.ariaDescribedByElements": null,
  "SVGStopElement.ariaDetailsElements": null,
  "SVGStopElement.ariaErrorMessageElements": null,
  "SVGStopElement.ariaFlowToElements": null,
  "SVGStopElement.ariaLabelledByElements": null,
  "SVGStopElement.ariaOwnsElements": null,
  "SVGStopElement.firstElementChild": null,
  "SVGStopElement.lastElementChild": null,
  "SVGStopElement.previousElementSibling": null,
  "SVGStopElement.nextElementSibling": null,
  "SVGStopElement.ownerSVGElement": null,
  "SVGStopElement.viewportElement": null,
  "SVGStyleElement.ownerDocument": null,
  "SVGStyleElement.parentNode": null,
  "SVGStyleElement.parentElement": null,
  "SVGStyleElement.childNodes": null,
  "SVGStyleElement.firstChild": null,
  "SVGStyleElement.lastChild": null,
  "SVGStyleElement.previousSibling": null,
  "SVGStyleElement.nextSibling": null,
  "SVGStyleElement.attributes": null,
  "SVGStyleElement.shadowRoot": null,
  "SVGStyleElement.assignedSlot": "slot",
  "SVGStyleElement.customElementRegistry": null,
  "SVGStyleElement.ariaActiveDescendantElement": null,
  "SVGStyleElement.ariaControlsElements": null,
  "SVGStyleElement.ariaDescribedByElements": null,
  "SVGStyleElement.ariaDetailsElements": null,
  "SVGStyleElement.ariaErrorMessageElements": null,
  "SVGStyleElement.ariaFlowToElements": null,
  "SVGStyleElement.ariaLabelledByElements": null,
  "SVGStyleElement.ariaOwnsElements": null,
  "SVGStyleElement.firstElementChild": null,
  "SVGStyleElement.lastElementChild": null,
  "SVGStyleElement.previousElementSibling": null,
  "SVGStyleElement.nextElementSibling": null,
  "SVGStyleElement.ownerSVGElement": null,
  "SVGStyleElement.viewportElement": null,
  "SVGSVGElement.ownerDocument": null,
  "SVGSVGElement.parentNode": null,
  "SVGSVGElement.parentElement": null,
  "SVGSVGElement.childNodes": null,
  "SVGSVGElement.firstChild": null,
  "SVGSVGElement.lastChild": null,
  "SVGSVGElement.previousSibling": null,
  "SVGSVGElement.nextSibling": null,
  "SVGSVGElement.attributes": null,
  "SVGSVGElement.shadowRoot": null,
  "SVGSVGElement.assignedSlot": "slot",
  "SVGSVGElement.customElementRegistry": null,
  "SVGSVGElement.ariaActiveDescendantElement": null,
  "SVGSVGElement.ariaControlsElements": null,
  "SVGSVGElement.ariaDescribedByElements": null,
  "SVGSVGElement.ariaDetailsElements": null,
  "SVGSVGElement.ariaErrorMessageElements": null,
  "SVGSVGElement.ariaFlowToElements": null,
  "SVGSVGElement.ariaLabelledByElements": null,
  "SVGSVGElement.ariaOwnsElements": null,
  "SVGSVGElement.firstElementChild": null,
  "SVGSVGElement.lastElementChild": null,
  "SVGSVGElement.previousElementSibling": null,
  "SVGSVGElement.nextElementSibling": null,
  "SVGSVGElement.ownerSVGElement": null,
  "SVGSVGElement.viewportElement": null,
  "SVGSVGElement.nearestViewportElement": null,
  "SVGSVGElement.farthestViewportElement": null,
  "SVGSwitchElement.ownerDocument": null,
  "SVGSwitchElement.parentNode": null,
  "SVGSwitchElement.parentElement": null,
  "SVGSwitchElement.childNodes": null,
  "SVGSwitchElement.firstChild": null,
  "SVGSwitchElement.lastChild": null,
  "SVGSwitchElement.previousSibling": null,
  "SVGSwitchElement.nextSibling": null,
  "SVGSwitchElement.attributes": null,
  "SVGSwitchElement.shadowRoot": null,
  "SVGSwitchElement.assignedSlot": "slot",
  "SVGSwitchElement.customElementRegistry": null,
  "SVGSwitchElement.ariaActiveDescendantElement": null,
  "SVGSwitchElement.ariaControlsElements": null,
  "SVGSwitchElement.ariaDescribedByElements": null,
  "SVGSwitchElement.ariaDetailsElements": null,
  "SVGSwitchElement.ariaErrorMessageElements": null,
  "SVGSwitchElement.ariaFlowToElements": null,
  "SVGSwitchElement.ariaLabelledByElements": null,
  "SVGSwitchElement.ariaOwnsElements": null,
  "SVGSwitchElement.firstElementChild": null,
  "SVGSwitchElement.lastElementChild": null,
  "SVGSwitchElement.previousElementSibling": null,
  "SVGSwitchElement.nextElementSibling": null,
  "SVGSwitchElement.ownerSVGElement": null,
  "SVGSwitchElement.viewportElement": null,
  "SVGSwitchElement.nearestViewportElement": null,
  "SVGSwitchElement.farthestViewportElement": null,
  "SVGSymbolElement.ownerDocument": null,
  "SVGSymbolElement.parentNode": null,
  "SVGSymbolElement.parentElement": null,
  "SVGSymbolElement.childNodes": null,
  "SVGSymbolElement.firstChild": null,
  "SVGSymbolElement.lastChild": null,
  "SVGSymbolElement.previousSibling": null,
  "SVGSymbolElement.nextSibling": null,
  "SVGSymbolElement.attributes": null,
  "SVGSymbolElement.shadowRoot": null,
  "SVGSymbolElement.assignedSlot": "slot",
  "SVGSymbolElement.customElementRegistry": null,
  "SVGSymbolElement.ariaActiveDescendantElement": null,
  "SVGSymbolElement.ariaControlsElements": null,
  "SVGSymbolElement.ariaDescribedByElements": null,
  "SVGSymbolElement.ariaDetailsElements": null,
  "SVGSymbolElement.ariaErrorMessageElements": null,
  "SVGSymbolElement.ariaFlowToElements": null,
  "SVGSymbolElement.ariaLabelledByElements": null,
  "SVGSymbolElement.ariaOwnsElements": null,
  "SVGSymbolElement.firstElementChild": null,
  "SVGSymbolElement.lastElementChild": null,
  "SVGSymbolElement.previousElementSibling": null,
  "SVGSymbolElement.nextElementSibling": null,
  "SVGSymbolElement.ownerSVGElement": null,
  "SVGSymbolElement.viewportElement": null,
  "SVGSymbolElement.nearestViewportElement": null,
  "SVGSymbolElement.farthestViewportElement": null,
  "SVGTextContentElement.ownerDocument": null,
  "SVGTextContentElement.parentNode": null,
  "SVGTextContentElement.parentElement": null,
  "SVGTextContentElement.childNodes": null,
  "SVGTextContentElement.firstChild": null,
  "SVGTextContentElement.lastChild": null,
  "SVGTextContentElement.previousSibling": null,
  "SVGTextContentElement.nextSibling": null,
  "SVGTextContentElement.attributes": null,
  "SVGTextContentElement.shadowRoot": null,
  "SVGTextContentElement.assignedSlot": "slot",
  "SVGTextContentElement.customElementRegistry": null,
  "SVGTextContentElement.ariaActiveDescendantElement": null,
  "SVGTextContentElement.ariaControlsElements": null,
  "SVGTextContentElement.ariaDescribedByElements": null,
  "SVGTextContentElement.ariaDetailsElements": null,
  "SVGTextContentElement.ariaErrorMessageElements": null,
  "SVGTextContentElement.ariaFlowToElements": null,
  "SVGTextContentElement.ariaLabelledByElements": null,
  "SVGTextContentElement.ariaOwnsElements": null,
  "SVGTextContentElement.firstElementChild": null,
  "SVGTextContentElement.lastElementChild": null,
  "SVGTextContentElement.previousElementSibling": null,
  "SVGTextContentElement.nextElementSibling": null,
  "SVGTextContentElement.ownerSVGElement": null,
  "SVGTextContentElement.viewportElement": null,
  "SVGTextContentElement.nearestViewportElement": null,
  "SVGTextContentElement.farthestViewportElement": null,
  "SVGTextElement.ownerDocument": null,
  "SVGTextElement.parentNode": null,
  "SVGTextElement.parentElement": null,
  "SVGTextElement.childNodes": null,
  "SVGTextElement.firstChild": null,
  "SVGTextElement.lastChild": null,
  "SVGTextElement.previousSibling": null,
  "SVGTextElement.nextSibling": null,
  "SVGTextElement.attributes": null,
  "SVGTextElement.shadowRoot": null,
  "SVGTextElement.assignedSlot": "slot",
  "SVGTextElement.customElementRegistry": null,
  "SVGTextElement.ariaActiveDescendantElement": null,
  "SVGTextElement.ariaControlsElements": null,
  "SVGTextElement.ariaDescribedByElements": null,
  "SVGTextElement.ariaDetailsElements": null,
  "SVGTextElement.ariaErrorMessageElements": null,
  "SVGTextElement.ariaFlowToElements": null,
  "SVGTextElement.ariaLabelledByElements": null,
  "SVGTextElement.ariaOwnsElements": null,
  "SVGTextElement.firstElementChild": null,
  "SVGTextElement.lastElementChild": null,
  "SVGTextElement.previousElementSibling": null,
  "SVGTextElement.nextElementSibling": null,
  "SVGTextElement.ownerSVGElement": null,
  "SVGTextElement.viewportElement": null,
  "SVGTextElement.nearestViewportElement": null,
  "SVGTextElement.farthestViewportElement": null,
  "SVGTextPathElement.ownerDocument": null,
  "SVGTextPathElement.parentNode": null,
  "SVGTextPathElement.parentElement": null,
  "SVGTextPathElement.childNodes": null,
  "SVGTextPathElement.firstChild": null,
  "SVGTextPathElement.lastChild": null,
  "SVGTextPathElement.previousSibling": null,
  "SVGTextPathElement.nextSibling": null,
  "SVGTextPathElement.attributes": null,
  "SVGTextPathElement.shadowRoot": null,
  "SVGTextPathElement.assignedSlot": "slot",
  "SVGTextPathElement.customElementRegistry": null,
  "SVGTextPathElement.ariaActiveDescendantElement": null,
  "SVGTextPathElement.ariaControlsElements": null,
  "SVGTextPathElement.ariaDescribedByElements": null,
  "SVGTextPathElement.ariaDetailsElements": null,
  "SVGTextPathElement.ariaErrorMessageElements": null,
  "SVGTextPathElement.ariaFlowToElements": null,
  "SVGTextPathElement.ariaLabelledByElements": null,
  "SVGTextPathElement.ariaOwnsElements": null,
  "SVGTextPathElement.firstElementChild": null,
  "SVGTextPathElement.lastElementChild": null,
  "SVGTextPathElement.previousElementSibling": null,
  "SVGTextPathElement.nextElementSibling": null,
  "SVGTextPathElement.ownerSVGElement": null,
  "SVGTextPathElement.viewportElement": null,
  "SVGTextPathElement.nearestViewportElement": null,
  "SVGTextPathElement.farthestViewportElement": null,
  "SVGTextPositioningElement.ownerDocument": null,
  "SVGTextPositioningElement.parentNode": null,
  "SVGTextPositioningElement.parentElement": null,
  "SVGTextPositioningElement.childNodes": null,
  "SVGTextPositioningElement.firstChild": null,
  "SVGTextPositioningElement.lastChild": null,
  "SVGTextPositioningElement.previousSibling": null,
  "SVGTextPositioningElement.nextSibling": null,
  "SVGTextPositioningElement.attributes": null,
  "SVGTextPositioningElement.shadowRoot": null,
  "SVGTextPositioningElement.assignedSlot": "slot",
  "SVGTextPositioningElement.customElementRegistry": null,
  "SVGTextPositioningElement.ariaActiveDescendantElement": null,
  "SVGTextPositioningElement.ariaControlsElements": null,
  "SVGTextPositioningElement.ariaDescribedByElements": null,
  "SVGTextPositioningElement.ariaDetailsElements": null,
  "SVGTextPositioningElement.ariaErrorMessageElements": null,
  "SVGTextPositioningElement.ariaFlowToElements": null,
  "SVGTextPositioningElement.ariaLabelledByElements": null,
  "SVGTextPositioningElement.ariaOwnsElements": null,
  "SVGTextPositioningElement.firstElementChild": null,
  "SVGTextPositioningElement.lastElementChild": null,
  "SVGTextPositioningElement.previousElementSibling": null,
  "SVGTextPositioningElement.nextElementSibling": null,
  "SVGTextPositioningElement.ownerSVGElement": null,
  "SVGTextPositioningElement.viewportElement": null,
  "SVGTextPositioningElement.nearestViewportElement": null,
  "SVGTextPositioningElement.farthestViewportElement": null,
  "SVGTitleElement.ownerDocument": null,
  "SVGTitleElement.parentNode": null,
  "SVGTitleElement.parentElement": null,
  "SVGTitleElement.childNodes": null,
  "SVGTitleElement.firstChild": null,
  "SVGTitleElement.lastChild": null,
  "SVGTitleElement.previousSibling": null,
  "SVGTitleElement.nextSibling": null,
  "SVGTitleElement.attributes": null,
  "SVGTitleElement.shadowRoot": null,
  "SVGTitleElement.assignedSlot": "slot",
  "SVGTitleElement.customElementRegistry": null,
  "SVGTitleElement.ariaActiveDescendantElement": null,
  "SVGTitleElement.ariaControlsElements": null,
  "SVGTitleElement.ariaDescribedByElements": null,
  "SVGTitleElement.ariaDetailsElements": null,
  "SVGTitleElement.ariaErrorMessageElements": null,
  "SVGTitleElement.ariaFlowToElements": null,
  "SVGTitleElement.ariaLabelledByElements": null,
  "SVGTitleElement.ariaOwnsElements": null,
  "SVGTitleElement.firstElementChild": null,
  "SVGTitleElement.lastElementChild": null,
  "SVGTitleElement.previousElementSibling": null,
  "SVGTitleElement.nextElementSibling": null,
  "SVGTitleElement.ownerSVGElement": null,
  "SVGTitleElement.viewportElement": null,
  "SVGTSpanElement.ownerDocument": null,
  "SVGTSpanElement.parentNode": null,
  "SVGTSpanElement.parentElement": null,
  "SVGTSpanElement.childNodes": null,
  "SVGTSpanElement.firstChild": null,
  "SVGTSpanElement.lastChild": null,
  "SVGTSpanElement.previousSibling": null,
  "SVGTSpanElement.nextSibling": null,
  "SVGTSpanElement.attributes": null,
  "SVGTSpanElement.shadowRoot": null,
  "SVGTSpanElement.assignedSlot": "slot",
  "SVGTSpanElement.customElementRegistry": null,
  "SVGTSpanElement.ariaActiveDescendantElement": null,
  "SVGTSpanElement.ariaControlsElements": null,
  "SVGTSpanElement.ariaDescribedByElements": null,
  "SVGTSpanElement.ariaDetailsElements": null,
  "SVGTSpanElement.ariaErrorMessageElements": null,
  "SVGTSpanElement.ariaFlowToElements": null,
  "SVGTSpanElement.ariaLabelledByElements": null,
  "SVGTSpanElement.ariaOwnsElements": null,
  "SVGTSpanElement.firstElementChild": null,
  "SVGTSpanElement.lastElementChild": null,
  "SVGTSpanElement.previousElementSibling": null,
  "SVGTSpanElement.nextElementSibling": null,
  "SVGTSpanElement.ownerSVGElement": null,
  "SVGTSpanElement.viewportElement": null,
  "SVGTSpanElement.nearestViewportElement": null,
  "SVGTSpanElement.farthestViewportElement": null,
  "SVGUseElement.ownerDocument": null,
  "SVGUseElement.parentNode": null,
  "SVGUseElement.parentElement": null,
  "SVGUseElement.childNodes": null,
  "SVGUseElement.firstChild": null,
  "SVGUseElement.lastChild": null,
  "SVGUseElement.previousSibling": null,
  "SVGUseElement.nextSibling": null,
  "SVGUseElement.attributes": null,
  "SVGUseElement.shadowRoot": null,
  "SVGUseElement.assignedSlot": "slot",
  "SVGUseElement.customElementRegistry": null,
  "SVGUseElement.ariaActiveDescendantElement": null,
  "SVGUseElement.ariaControlsElements": null,
  "SVGUseElement.ariaDescribedByElements": null,
  "SVGUseElement.ariaDetailsElements": null,
  "SVGUseElement.ariaErrorMessageElements": null,
  "SVGUseElement.ariaFlowToElements": null,
  "SVGUseElement.ariaLabelledByElements": null,
  "SVGUseElement.ariaOwnsElements": null,
  "SVGUseElement.firstElementChild": null,
  "SVGUseElement.lastElementChild": null,
  "SVGUseElement.previousElementSibling": null,
  "SVGUseElement.nextElementSibling": null,
  "SVGUseElement.ownerSVGElement": null,
  "SVGUseElement.viewportElement": null,
  "SVGUseElement.nearestViewportElement": null,
  "SVGUseElement.farthestViewportElement": null,
  "SVGViewElement.ownerDocument": null,
  "SVGViewElement.parentNode": null,
  "SVGViewElement.parentElement": null,
  "SVGViewElement.childNodes": null,
  "SVGViewElement.firstChild": null,
  "SVGViewElement.lastChild": null,
  "SVGViewElement.previousSibling": null,
  "SVGViewElement.nextSibling": null,
  "SVGViewElement.attributes": null,
  "SVGViewElement.shadowRoot": null,
  "SVGViewElement.assignedSlot": "slot",
  "SVGViewElement.customElementRegistry": null,
  "SVGViewElement.ariaActiveDescendantElement": null,
  "SVGViewElement.ariaControlsElements": null,
  "SVGViewElement.ariaDescribedByElements": null,
  "SVGViewElement.ariaDetailsElements": null,
  "SVGViewElement.ariaErrorMessageElements": null,
  "SVGViewElement.ariaFlowToElements": null,
  "SVGViewElement.ariaLabelledByElements": null,
  "SVGViewElement.ariaOwnsElements": null,
  "SVGViewElement.firstElementChild": null,
  "SVGViewElement.lastElementChild": null,
  "SVGViewElement.previousElementSibling": null,
  "SVGViewElement.nextElementSibling": null,
  "SVGViewElement.ownerSVGElement": null,
  "SVGViewElement.viewportElement": null,
  "StaticSelection.anchorNode": null,
  "StaticSelection.focusNode": null,
  "InteractionContentfulPaint.element": null,
  "LargestContentfulPaint.element": null,
  "LayoutShiftAttribution.node": null,
  "PerformanceContainerTiming.rootElement": null,
  "PerformanceContainerTiming.lastPaintedElement": null,
  "PerformanceElementTiming.element": null,
  "PerformanceEventTiming.target": null,
  "ViewTransition.transitionRoot": null,
  "XPathResult.singleNodeValue": null,
  "XMLHttpRequest.responseXML": null,
  "CanvasRenderingContext2D.canvas": "canvas",
  "ImageBitmapRenderingContext.canvas": "canvas",
  "DelegatedInkTrailPresenter.presentationArea": null,
  "CanvasCaptureMediaStreamTrack.canvas": "canvas",
  "AudioContext.destination": null,
  "BaseAudioContext.destination": null,
  "MediaElementAudioSourceNode.mediaElement": null,
  "OfflineAudioContext.destination": null,
  "WebGL2RenderingContext.canvas": "canvas",
  "WebGL2RenderingContextWebGPU.canvas": "canvas",
  "WebGLRenderingContext.canvas": "canvas",
  "WebGLRenderingContextWebGPU.canvas": "canvas",
  "GPUCanvasContext.canvas": "canvas"
};

// Resolve a member access on a known interface to its DOM element info.
// e.g., getDOMPropertyInfo("Document", "head") → { tag: "head", isDomAttached: true }
// e.g., getDOMPropertyInfo("Document", "body") → { tag: null, isDomAttached: true }
// Returns null if the property doesn't return an Element type.
export function getDOMPropertyInfo(interfaceName, propName) {
  const key = interfaceName + '.' + propName;
  if (key in DOM_PROPERTIES) {
    return { tag: DOM_PROPERTIES[key], isDomAttached: true };
  }
  return null;
}

// Per-interface DOM property index
const DOM_PROPS_BY_IFACE = {
  "Document": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "doctype": {
      "tag": null
    },
    "documentElement": {
      "tag": null
    },
    "body": {
      "tag": null
    },
    "head": {
      "tag": "head"
    },
    "scrollingElement": {
      "tag": null
    },
    "webkitCurrentFullScreenElement": {
      "tag": null
    },
    "webkitFullscreenElement": {
      "tag": null
    },
    "rootElement": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "activeElement": {
      "tag": null
    },
    "pointerLockElement": {
      "tag": null
    },
    "fullscreenElement": {
      "tag": null
    },
    "pictureInPictureElement": {
      "tag": null
    },
    "customElementRegistry": {
      "tag": null
    }
  },
  "KeyframeEffect": {
    "target": {
      "tag": null
    }
  },
  "ScrollTimeline": {
    "source": {
      "tag": null
    }
  },
  "ViewTimeline": {
    "source": {
      "tag": null
    },
    "subject": {
      "tag": null
    }
  },
  "CaretPosition": {
    "offsetNode": {
      "tag": null
    }
  },
  "Element": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    }
  },
  "CSSStyleSheet": {
    "ownerNode": {
      "tag": null
    }
  },
  "StyleSheet": {
    "ownerNode": {
      "tag": null
    }
  },
  "AbstractRange": {
    "startContainer": {
      "tag": null
    },
    "endContainer": {
      "tag": null
    }
  },
  "Attr": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "ownerElement": {
      "tag": null
    }
  },
  "CDATASection": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    }
  },
  "CharacterData": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    }
  },
  "Comment": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    }
  },
  "CSSPseudoElement": {
    "element": {
      "tag": null
    },
    "parent": {
      "tag": null
    }
  },
  "DocumentFragment": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    }
  },
  "DocumentType": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    }
  },
  "MutationRecord": {
    "target": {
      "tag": null
    },
    "addedNodes": {
      "tag": null
    },
    "removedNodes": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    }
  },
  "Node": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    }
  },
  "NodeIterator": {
    "root": {
      "tag": null
    },
    "referenceNode": {
      "tag": null
    },
    "filter": {
      "tag": null
    }
  },
  "OpaqueRange": {
    "startContainer": {
      "tag": null
    },
    "endContainer": {
      "tag": null
    }
  },
  "ProcessingInstruction": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    }
  },
  "Range": {
    "startContainer": {
      "tag": null
    },
    "endContainer": {
      "tag": null
    },
    "commonAncestorContainer": {
      "tag": null
    }
  },
  "ShadowRoot": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "mode": {
      "tag": null
    },
    "host": {
      "tag": null
    },
    "activeElement": {
      "tag": null
    },
    "pointerLockElement": {
      "tag": null
    },
    "fullscreenElement": {
      "tag": null
    },
    "pictureInPictureElement": {
      "tag": null
    },
    "customElementRegistry": {
      "tag": null
    }
  },
  "StaticRange": {
    "startContainer": {
      "tag": null
    },
    "endContainer": {
      "tag": null
    }
  },
  "Internals": {
    "visibleSelectionAnchorNode": {
      "tag": null
    },
    "visibleSelectionFocusNode": {
      "tag": null
    }
  },
  "Text": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    }
  },
  "TreeWalker": {
    "root": {
      "tag": null
    },
    "filter": {
      "tag": null
    },
    "currentNode": {
      "tag": null
    }
  },
  "XMLDocument": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "doctype": {
      "tag": null
    },
    "documentElement": {
      "tag": null
    },
    "body": {
      "tag": null
    },
    "head": {
      "tag": "head"
    },
    "scrollingElement": {
      "tag": null
    },
    "webkitCurrentFullScreenElement": {
      "tag": null
    },
    "webkitFullscreenElement": {
      "tag": null
    },
    "rootElement": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "activeElement": {
      "tag": null
    },
    "pointerLockElement": {
      "tag": null
    },
    "fullscreenElement": {
      "tag": null
    },
    "pictureInPictureElement": {
      "tag": null
    },
    "customElementRegistry": {
      "tag": null
    }
  },
  "Selection": {
    "anchorNode": {
      "tag": null
    },
    "focusNode": {
      "tag": null
    },
    "baseNode": {
      "tag": null
    },
    "extentNode": {
      "tag": null
    }
  },
  "AnimationEvent": {
    "pseudoTarget": {
      "tag": null
    }
  },
  "CommandEvent": {
    "source": {
      "tag": null
    }
  },
  "CompositionEvent": {
    "pseudoTarget": {
      "tag": null
    }
  },
  "DragEvent": {
    "pseudoTarget": {
      "tag": null
    },
    "fromElement": {
      "tag": null
    },
    "toElement": {
      "tag": null
    }
  },
  "FocusEvent": {
    "pseudoTarget": {
      "tag": null
    }
  },
  "InputEvent": {
    "pseudoTarget": {
      "tag": null
    }
  },
  "InterestEvent": {
    "source": {
      "tag": null
    }
  },
  "KeyboardEvent": {
    "pseudoTarget": {
      "tag": null
    }
  },
  "MouseEvent": {
    "pseudoTarget": {
      "tag": null
    },
    "fromElement": {
      "tag": null
    },
    "toElement": {
      "tag": null
    }
  },
  "PointerEvent": {
    "pseudoTarget": {
      "tag": null
    },
    "fromElement": {
      "tag": null
    },
    "toElement": {
      "tag": null
    }
  },
  "TextEvent": {
    "pseudoTarget": {
      "tag": null
    }
  },
  "ToggleEvent": {
    "source": {
      "tag": null
    }
  },
  "TouchEvent": {
    "pseudoTarget": {
      "tag": null
    }
  },
  "TransitionEvent": {
    "pseudoTarget": {
      "tag": null
    }
  },
  "UIEvent": {
    "pseudoTarget": {
      "tag": null
    }
  },
  "WheelEvent": {
    "pseudoTarget": {
      "tag": null
    },
    "fromElement": {
      "tag": null
    },
    "toElement": {
      "tag": null
    }
  },
  "Window": {
    "document": {
      "tag": null
    },
    "customElements": {
      "tag": null
    },
    "frameElement": {
      "tag": null
    }
  },
  "HighlightPointerEvent": {
    "pseudoTarget": {
      "tag": null
    },
    "fromElement": {
      "tag": null
    },
    "toElement": {
      "tag": null
    }
  },
  "CanvasPaintEvent": {
    "changedElements": {
      "tag": null
    }
  },
  "HTMLCanvasElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "ElementInternals": {
    "form": {
      "tag": null
    },
    "labels": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    }
  },
  "HTMLFencedFrameElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLButtonElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    },
    "form": {
      "tag": null
    },
    "labels": {
      "tag": null
    },
    "popoverTargetElement": {
      "tag": null
    },
    "commandForElement": {
      "tag": null
    },
    "interestForElement": {
      "tag": null
    }
  },
  "HTMLDataListElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLFieldSetElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    },
    "form": {
      "tag": null
    }
  },
  "HTMLFormElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLInputElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    },
    "form": {
      "tag": null
    },
    "list": {
      "tag": null
    },
    "labels": {
      "tag": null
    },
    "popoverTargetElement": {
      "tag": null
    }
  },
  "HTMLLabelElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    },
    "form": {
      "tag": null
    },
    "control": {
      "tag": null
    }
  },
  "HTMLLegendElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    },
    "form": {
      "tag": null
    }
  },
  "HTMLOptionElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    },
    "form": {
      "tag": null
    }
  },
  "HTMLOptGroupElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLOutputElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    },
    "form": {
      "tag": null
    },
    "labels": {
      "tag": null
    }
  },
  "HTMLSelectedContentElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLSelectElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    },
    "form": {
      "tag": null
    },
    "labels": {
      "tag": null
    },
    "selectedContentElement": {
      "tag": "selectedcontent"
    }
  },
  "HTMLTextAreaElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    },
    "form": {
      "tag": null
    },
    "labels": {
      "tag": null
    }
  },
  "SubmitEvent": {
    "submitter": {
      "tag": null
    }
  },
  "HTMLAnchorElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    },
    "interestForElement": {
      "tag": null
    }
  },
  "HTMLAreaElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    },
    "interestForElement": {
      "tag": null
    }
  },
  "HTMLBaseElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLBodyElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLBRElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLCredentialElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLDataElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLDetailsElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLDialogElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLDirectoryElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLDivElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLDListElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLDocument": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "doctype": {
      "tag": null
    },
    "documentElement": {
      "tag": null
    },
    "body": {
      "tag": null
    },
    "head": {
      "tag": "head"
    },
    "scrollingElement": {
      "tag": null
    },
    "webkitCurrentFullScreenElement": {
      "tag": null
    },
    "webkitFullscreenElement": {
      "tag": null
    },
    "rootElement": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "activeElement": {
      "tag": null
    },
    "pointerLockElement": {
      "tag": null
    },
    "fullscreenElement": {
      "tag": null
    },
    "pictureInPictureElement": {
      "tag": null
    },
    "customElementRegistry": {
      "tag": null
    }
  },
  "HTMLElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLEmbedElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLFontElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLFrameElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    },
    "contentDocument": {
      "tag": null
    }
  },
  "HTMLFrameSetElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLGeolocationElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLHeadingElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLHeadElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLHRElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLHtmlElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLIFrameElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    },
    "contentDocument": {
      "tag": null
    }
  },
  "HTMLImageElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLInstallElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLLinkElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLLIElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLLoginElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLMapElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLMarqueeElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLMenuBarElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLMenuElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLMenuItemElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    },
    "commandForElement": {
      "tag": null
    },
    "interestForElement": {
      "tag": null
    }
  },
  "HTMLMenuListElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLMetaElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLMeterElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    },
    "labels": {
      "tag": null
    }
  },
  "HTMLModElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLObjectElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    },
    "form": {
      "tag": null
    },
    "contentDocument": {
      "tag": null
    }
  },
  "HTMLOListElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLParagraphElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLParamElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLPictureElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLPreElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLProgressElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    },
    "labels": {
      "tag": null
    }
  },
  "HTMLQuoteElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLScriptElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLSlotElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLSourceElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLSpanElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLStyleElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLTableCaptionElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLTableCellElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLTableColElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLTableElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    },
    "caption": {
      "tag": "caption"
    },
    "tHead": {
      "tag": "tbody"
    },
    "tFoot": {
      "tag": "tbody"
    }
  },
  "HTMLTableRowElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLTableSectionElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLTemplateElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    },
    "content": {
      "tag": null
    }
  },
  "HTMLTimeElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLTitleElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLUListElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLUnknownElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLUserMediaElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLAudioElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLMediaElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLVideoElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "HTMLTrackElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "scrollParent": {
      "tag": null
    },
    "offsetParent": {
      "tag": null
    }
  },
  "IntersectionObserver": {
    "root": {
      "tag": null
    }
  },
  "IntersectionObserverEntry": {
    "target": {
      "tag": null
    }
  },
  "MathMLElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    }
  },
  "NavigateEvent": {
    "sourceElement": {
      "tag": null
    }
  },
  "OverscrollEvent": {
    "overscrollElement": {
      "tag": null
    }
  },
  "ResizeObserverEntry": {
    "target": {
      "tag": null
    }
  },
  "SnapEvent": {
    "snapTargetBlock": {
      "tag": null
    },
    "snapTargetInline": {
      "tag": null
    }
  },
  "SVGAnimateElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "targetElement": {
      "tag": null
    }
  },
  "SVGAnimateMotionElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "targetElement": {
      "tag": null
    }
  },
  "SVGAnimateTransformElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "targetElement": {
      "tag": null
    }
  },
  "SVGAnimationElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "targetElement": {
      "tag": null
    }
  },
  "SVGAElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "nearestViewportElement": {
      "tag": null
    },
    "farthestViewportElement": {
      "tag": null
    },
    "interestForElement": {
      "tag": null
    }
  },
  "SVGCircleElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "nearestViewportElement": {
      "tag": null
    },
    "farthestViewportElement": {
      "tag": null
    }
  },
  "SVGClipPathElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGComponentTransferFunctionElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGDefsElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "nearestViewportElement": {
      "tag": null
    },
    "farthestViewportElement": {
      "tag": null
    }
  },
  "SVGDescElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGEllipseElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "nearestViewportElement": {
      "tag": null
    },
    "farthestViewportElement": {
      "tag": null
    }
  },
  "SVGFEBlendElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGFEColorMatrixElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGFEComponentTransferElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGFECompositeElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGFEConvolveMatrixElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGFEDiffuseLightingElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGFEDisplacementMapElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGFEDistantLightElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGFEDropShadowElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGFEFloodElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGFEFuncAElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGFEFuncBElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGFEFuncGElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGFEFuncRElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGFEGaussianBlurElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGFEImageElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGFEMergeElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGFEMergeNodeElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGFEMorphologyElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGFEOffsetElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGFEPointLightElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGFESpecularLightingElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGFESpotLightElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGFETileElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGFETurbulenceElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGFilterElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGForeignObjectElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "nearestViewportElement": {
      "tag": null
    },
    "farthestViewportElement": {
      "tag": null
    }
  },
  "SVGGeometryElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "nearestViewportElement": {
      "tag": null
    },
    "farthestViewportElement": {
      "tag": null
    }
  },
  "SVGGradientElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGGraphicsElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "nearestViewportElement": {
      "tag": null
    },
    "farthestViewportElement": {
      "tag": null
    }
  },
  "SVGGElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "nearestViewportElement": {
      "tag": null
    },
    "farthestViewportElement": {
      "tag": null
    }
  },
  "SVGImageElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "nearestViewportElement": {
      "tag": null
    },
    "farthestViewportElement": {
      "tag": null
    }
  },
  "SVGLinearGradientElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGLineElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "nearestViewportElement": {
      "tag": null
    },
    "farthestViewportElement": {
      "tag": null
    }
  },
  "SVGMarkerElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGMaskElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGMetadataElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGMPathElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGPathElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "nearestViewportElement": {
      "tag": null
    },
    "farthestViewportElement": {
      "tag": null
    }
  },
  "SVGPatternElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGPolygonElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "nearestViewportElement": {
      "tag": null
    },
    "farthestViewportElement": {
      "tag": null
    }
  },
  "SVGPolylineElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "nearestViewportElement": {
      "tag": null
    },
    "farthestViewportElement": {
      "tag": null
    }
  },
  "SVGRadialGradientElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGRectElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "nearestViewportElement": {
      "tag": null
    },
    "farthestViewportElement": {
      "tag": null
    }
  },
  "SVGScriptElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGSetElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "targetElement": {
      "tag": null
    }
  },
  "SVGStopElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGStyleElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGSVGElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "nearestViewportElement": {
      "tag": null
    },
    "farthestViewportElement": {
      "tag": null
    }
  },
  "SVGSwitchElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "nearestViewportElement": {
      "tag": null
    },
    "farthestViewportElement": {
      "tag": null
    }
  },
  "SVGSymbolElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "nearestViewportElement": {
      "tag": null
    },
    "farthestViewportElement": {
      "tag": null
    }
  },
  "SVGTextContentElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "nearestViewportElement": {
      "tag": null
    },
    "farthestViewportElement": {
      "tag": null
    }
  },
  "SVGTextElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "nearestViewportElement": {
      "tag": null
    },
    "farthestViewportElement": {
      "tag": null
    }
  },
  "SVGTextPathElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "nearestViewportElement": {
      "tag": null
    },
    "farthestViewportElement": {
      "tag": null
    }
  },
  "SVGTextPositioningElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "nearestViewportElement": {
      "tag": null
    },
    "farthestViewportElement": {
      "tag": null
    }
  },
  "SVGTitleElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "SVGTSpanElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "nearestViewportElement": {
      "tag": null
    },
    "farthestViewportElement": {
      "tag": null
    }
  },
  "SVGUseElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    },
    "nearestViewportElement": {
      "tag": null
    },
    "farthestViewportElement": {
      "tag": null
    }
  },
  "SVGViewElement": {
    "ownerDocument": {
      "tag": null
    },
    "parentNode": {
      "tag": null
    },
    "parentElement": {
      "tag": null
    },
    "childNodes": {
      "tag": null
    },
    "firstChild": {
      "tag": null
    },
    "lastChild": {
      "tag": null
    },
    "previousSibling": {
      "tag": null
    },
    "nextSibling": {
      "tag": null
    },
    "attributes": {
      "tag": null
    },
    "shadowRoot": {
      "tag": null
    },
    "assignedSlot": {
      "tag": "slot"
    },
    "customElementRegistry": {
      "tag": null
    },
    "ariaActiveDescendantElement": {
      "tag": null
    },
    "ariaControlsElements": {
      "tag": null
    },
    "ariaDescribedByElements": {
      "tag": null
    },
    "ariaDetailsElements": {
      "tag": null
    },
    "ariaErrorMessageElements": {
      "tag": null
    },
    "ariaFlowToElements": {
      "tag": null
    },
    "ariaLabelledByElements": {
      "tag": null
    },
    "ariaOwnsElements": {
      "tag": null
    },
    "firstElementChild": {
      "tag": null
    },
    "lastElementChild": {
      "tag": null
    },
    "previousElementSibling": {
      "tag": null
    },
    "nextElementSibling": {
      "tag": null
    },
    "ownerSVGElement": {
      "tag": null
    },
    "viewportElement": {
      "tag": null
    }
  },
  "StaticSelection": {
    "anchorNode": {
      "tag": null
    },
    "focusNode": {
      "tag": null
    }
  },
  "InteractionContentfulPaint": {
    "element": {
      "tag": null
    }
  },
  "LargestContentfulPaint": {
    "element": {
      "tag": null
    }
  },
  "LayoutShiftAttribution": {
    "node": {
      "tag": null
    }
  },
  "PerformanceContainerTiming": {
    "rootElement": {
      "tag": null
    },
    "lastPaintedElement": {
      "tag": null
    }
  },
  "PerformanceElementTiming": {
    "element": {
      "tag": null
    }
  },
  "PerformanceEventTiming": {
    "target": {
      "tag": null
    }
  },
  "ViewTransition": {
    "transitionRoot": {
      "tag": null
    }
  },
  "XPathResult": {
    "singleNodeValue": {
      "tag": null
    }
  },
  "XMLHttpRequest": {
    "responseXML": {
      "tag": null
    }
  },
  "CanvasRenderingContext2D": {
    "canvas": {
      "tag": "canvas"
    }
  },
  "ImageBitmapRenderingContext": {
    "canvas": {
      "tag": "canvas"
    }
  },
  "DelegatedInkTrailPresenter": {
    "presentationArea": {
      "tag": null
    }
  },
  "CanvasCaptureMediaStreamTrack": {
    "canvas": {
      "tag": "canvas"
    }
  },
  "AudioContext": {
    "destination": {
      "tag": null
    }
  },
  "BaseAudioContext": {
    "destination": {
      "tag": null
    }
  },
  "MediaElementAudioSourceNode": {
    "mediaElement": {
      "tag": null
    }
  },
  "OfflineAudioContext": {
    "destination": {
      "tag": null
    }
  },
  "WebGL2RenderingContext": {
    "canvas": {
      "tag": "canvas"
    }
  },
  "WebGL2RenderingContextWebGPU": {
    "canvas": {
      "tag": "canvas"
    }
  },
  "WebGLRenderingContext": {
    "canvas": {
      "tag": "canvas"
    }
  },
  "WebGLRenderingContextWebGPU": {
    "canvas": {
      "tag": "canvas"
    }
  },
  "GPUCanvasContext": {
    "canvas": {
      "tag": "canvas"
    }
  }
};

// Get all DOM-producing properties for a given interface.
// Returns { propName: { tag } } or null.
export function getDOMPropertiesForInterface(interfaceName) {
  return DOM_PROPS_BY_IFACE[interfaceName] || null;
}
