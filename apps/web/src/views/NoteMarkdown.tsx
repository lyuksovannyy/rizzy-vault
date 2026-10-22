// SPDX-License-Identifier: AGPL-3.0-only

// A Secure Note's `item.notes`, rendered from its Markdown (ADR 0062; THREAT_MODEL INV-88).
// `parseNote` (`../markdown.ts`) turns the stored text into a closed AST; this module renders that AST
// to React elements, one fixed element per variant, every one with this module's own fixed
// CSS class and no other attribute (§8). Text reaches the DOM only as React text children,
// which React escapes, so a `<script>` in a note is those eight visible characters (§9). No
// HTML string is ever built and no raw-HTML sink is used (§3; ADR 0014 §2): every path into
// the renderer goes through the parser's fixed variant set, which is the sanitization pass.
//
// Each renderer is a `switch` over its variant union with no `default` branch: the functions
// declare a non-`undefined` return type, so a variant added to the AST and not handled here is a
// compile error (TS2366), not a rendering hole (§3).
//
// Scope (§2): only the Secure Note read view uses this (`ItemView.tsx`). Every other item type's
// notes, the editor, history, conflict chooser, copy and export keep the plain stored text
// (§2, §12).
import { Fragment, type ReactElement, type ReactNode, useMemo } from "react";

import { type Block, type Inline, type Line, type NoteDocument, parseNote } from "../markdown.ts";

function renderInline(node: Inline, key: number): ReactNode {
  switch (node.kind) {
    case "text":
      return <Fragment key={key}>{node.text}</Fragment>;
    case "strong":
      return (
        <strong key={key} className="md-strong">
          {renderInlines(node.children)}
        </strong>
      );
    case "em":
      return (
        <em key={key} className="md-em">
          {renderInlines(node.children)}
        </em>
      );
    case "del":
      return (
        <del key={key} className="md-del">
          {renderInlines(node.children)}
        </del>
      );
    case "code":
      return (
        <code key={key} className="md-code">
          {node.text}
        </code>
      );
  }
}

function renderInlines(nodes: readonly Inline[]): ReactNode[] {
  return nodes.map(renderInline);
}

/** A paragraph's lines, with a line break between each two (ADR 0062 §5). */
function renderLines(lines: readonly Line[]): ReactNode[] {
  return lines.map((line, i) => (
    <Fragment key={i}>
      {i > 0 && <br className="md-br" />}
      {renderInlines(line)}
    </Fragment>
  ));
}

function renderHeading(block: Extract<Block, { kind: "heading" }>, key: number): ReactElement {
  const children = renderInlines(block.content);
  switch (block.level) {
    case 1:
      return <h1 key={key} className="md-h1">{children}</h1>;
    case 2:
      return <h2 key={key} className="md-h2">{children}</h2>;
    case 3:
      return <h3 key={key} className="md-h3">{children}</h3>;
    case 4:
      return <h4 key={key} className="md-h4">{children}</h4>;
    case 5:
      return <h5 key={key} className="md-h5">{children}</h5>;
    case 6:
      return <h6 key={key} className="md-h6">{children}</h6>;
  }
}

function renderBlock(block: Block, key: number): ReactElement {
  switch (block.kind) {
    case "heading":
      return renderHeading(block, key);
    case "paragraph":
      return (
        <p key={key} className="md-p">
          {renderLines(block.lines)}
        </p>
      );
    case "codeBlock":
      return (
        <pre key={key} className="md-pre">
          <code className="md-pre-code">{block.text}</code>
        </pre>
      );
    case "blockquote":
      return (
        <blockquote key={key} className="md-blockquote">
          {block.paragraphs.map((lines, i) => (
            <p key={i} className="md-p">
              {renderLines(lines)}
            </p>
          ))}
        </blockquote>
      );
    case "list": {
      const items = block.items.map((line, i) => (
        <li key={i} className="md-li">
          {renderInlines(line)}
        </li>
      ));
      return block.ordered ? (
        <ol key={key} className="md-ol">
          {items}
        </ol>
      ) : (
        <ul key={key} className="md-ul">
          {items}
        </ul>
      );
    }
    case "rule":
      return <hr key={key} className="md-hr" />;
  }
}

/** Renders a parsed note. The plain fallback (§11) is the same plain text every other field
 * shows; the Markdown root carries `md-note`. */
export function renderNote(doc: NoteDocument): ReactElement {
  switch (doc.kind) {
    case "plain":
      return <span className="field-value">{doc.text}</span>;
    case "markdown":
      return <div className="field-value md-note">{doc.blocks.map(renderBlock)}</div>;
  }
}

/** A Secure Note's notes, rendered from their Markdown source (module docs). */
export function NoteMarkdown(props: { readonly source: string }) {
  const doc = useMemo(() => parseNote(props.source), [props.source]);
  return renderNote(doc);
}
