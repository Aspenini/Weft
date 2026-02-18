use std::collections::HashMap;

pub struct CompileOutput {
    pub html: String,
    pub meta: HashMap<String, String>,
    pub with_motion: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Block {
    Gap,
    Hr,
    CodeBlock {
        language: Option<String>,
        code: String,
    },
    Heading {
        level: u8,
        text: String,
        tags: Vec<String>,
    },
    Image {
        alt: String,
        src: String,
        tags: Vec<String>,
    },
    Paragraph {
        text: String,
        tags: Vec<String>,
    },
    Card {
        items: Vec<Block>,
    },
}

#[derive(Clone, Debug)]
enum InlineNode {
    Text(String),
    Tag {
        tag: String,
        children: Vec<InlineNode>,
        raw_open: String,
    },
}

#[derive(Clone, Debug)]
struct TagFrame {
    tag: Option<String>,
    children: Vec<InlineNode>,
    raw_open: String,
}

#[derive(Clone, Copy)]
struct Theme {
    bg: &'static str,
    text: &'static str,
    muted: &'static str,
    panel: &'static str,
    panel_line: &'static str,
    accent: &'static str,
}

#[derive(Clone)]
struct ResolvedTheme {
    bg: &'static str,
    text: &'static str,
    muted: &'static str,
    panel: &'static str,
    panel_line: &'static str,
    accent: String,
}

const DEFAULT_THEME: Theme = Theme {
    bg: "#fff8ef",
    text: "#1f232b",
    muted: "#5d6675",
    panel: "#ffffff",
    panel_line: "#e8dfce",
    accent: "#1f78c8",
};

const SLATE_THEME: Theme = Theme {
    bg: "#f0f4fb",
    text: "#111827",
    muted: "#5b6473",
    panel: "#ffffff",
    panel_line: "#d8e0ef",
    accent: "#1e55d6",
};

const INK_THEME: Theme = Theme {
    bg: "#151922",
    text: "#eef2ff",
    muted: "#acb8d6",
    panel: "#1d2330",
    panel_line: "#2a3345",
    accent: "#69a4ff",
};

const MOTION_SCRIPT: &str = r#"(function(){
  var reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  if (reduce) {
    document.querySelectorAll('.fade').forEach(function(el){
      el.style.opacity = '1';
      el.style.transform = 'none';
    });
    return;
  }

  var faders = document.querySelectorAll('.fade');
  if ('IntersectionObserver' in window) {
    var io = new IntersectionObserver(function(entries){
      entries.forEach(function(entry){
        if (entry.isIntersecting) {
          entry.target.animate([
            { opacity: 0, transform: 'translateY(16px)' },
            { opacity: 1, transform: 'translateY(0)' }
          ], { duration: 500, easing: 'ease-out', fill: 'forwards' });
          io.unobserve(entry.target);
        }
      });
    }, { threshold: 0.12 });
    faders.forEach(function(el){ io.observe(el); });
  } else {
    faders.forEach(function(el){
      el.style.opacity = '1';
      el.style.transform = 'none';
    });
  }

  document.querySelectorAll('.spin').forEach(function(el){
    el.animate(
      [{ transform: 'rotate(0deg)' }, { transform: 'rotate(360deg)' }],
      { duration: 2300, iterations: Infinity, easing: 'linear' }
    );
  });
})();"#;

pub fn compile_weft(source: &str) -> CompileOutput {
    let normalized = normalize_newlines(source);
    let lines: Vec<&str> = normalized.split('\n').collect();
    let (meta, content_start_idx) = parse_metadata(&lines);
    let blocks = parse_structure(&lines[content_start_idx..]);
    let content = render_blocks(&blocks);
    let with_motion = collect_motion(&blocks);
    let theme = theme_from_meta(&meta);

    let title = meta.get("title").map(String::as_str).unwrap_or("Weft Page");
    let desc = meta
        .get("desc")
        .map(String::as_str)
        .unwrap_or("Compiled from Weft");

    let style = generate_style(&theme);
    let script_html = if with_motion {
        format!("<script>{MOTION_SCRIPT}</script>")
    } else {
        String::new()
    };

    let html = format!(
        "<!doctype html>\n\
<html lang=\"en\">\n\
<head>\n\
<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n\
<title>{}</title>\n\
<meta name=\"description\" content=\"{}\">\n\
<style>{}</style>\n\
</head>\n\
<body>\n\
<main>{}</main>\n\
{}\n\
</body>\n\
</html>",
        escape_html(title),
        escape_html(desc),
        style,
        content,
        script_html
    );

    CompileOutput {
        html,
        meta,
        with_motion,
    }
}

fn normalize_newlines(input: &str) -> String {
    let normalized = input.replace("\r\n", "\n").replace('\r', "\n");
    if let Some(stripped) = normalized.strip_prefix('\u{feff}') {
        stripped.to_string()
    } else {
        normalized
    }
}

fn escape_html(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        push_escaped_char(ch, &mut out);
    }
    out
}

fn push_escaped_char(ch: char, out: &mut String) {
    match ch {
        '&' => out.push_str("&amp;"),
        '<' => out.push_str("&lt;"),
        '>' => out.push_str("&gt;"),
        '"' => out.push_str("&quot;"),
        '\'' => out.push_str("&#39;"),
        _ => out.push(ch),
    }
}

fn parse_metadata(lines: &[&str]) -> (HashMap<String, String>, usize) {
    let mut meta = HashMap::new();
    let mut idx = 0;

    while idx < lines.len() {
        let trimmed = lines[idx].trim();
        if trimmed.is_empty() {
            idx += 1;
            continue;
        }
        if !trimmed.starts_with('@') {
            break;
        }

        if let Some((key, value)) = parse_metadata_line(trimmed) {
            meta.insert(key, value);
        }
        idx += 1;
    }

    (meta, idx)
}

fn parse_metadata_line(line: &str) -> Option<(String, String)> {
    let mut chars = line.chars();
    if chars.next()? != '@' {
        return None;
    }

    let mut key_end = None;
    let mut iter = line.char_indices();
    iter.next();

    let (_, first) = iter.next()?;
    if !first.is_ascii_alphabetic() {
        return None;
    }

    for (idx, ch) in line.char_indices().skip(2) {
        if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
            continue;
        }
        key_end = Some(idx);
        break;
    }

    let key_end = key_end.unwrap_or(line.len());
    let key = line[1..key_end].to_ascii_lowercase();
    let value = line[key_end..].trim().to_string();
    Some((key, value))
}

fn parse_structure(lines: &[&str]) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut inside_card = false;
    let mut card_lines: Vec<&str> = Vec::new();
    let mut card_inside_code_fence = false;
    let mut inside_code_fence = false;
    let mut code_fence_lang: Option<String> = None;
    let mut code_fence_lines: Vec<&str> = Vec::new();

    for raw in lines {
        if inside_code_fence {
            if is_fence_close(raw) {
                blocks.push(code_block_from_lines(
                    code_fence_lang.take(),
                    &code_fence_lines,
                ));
                code_fence_lines.clear();
                inside_code_fence = false;
            } else {
                code_fence_lines.push(raw);
            }
            continue;
        }

        if inside_card {
            if card_inside_code_fence {
                card_lines.push(raw);
                if is_fence_close(raw) {
                    card_inside_code_fence = false;
                }
                continue;
            }

            if parse_fence_start(raw).is_some() {
                card_inside_code_fence = true;
                card_lines.push(raw);
                continue;
            }

            if raw.trim() == ":::" {
                let items = parse_card_items(&card_lines);
                blocks.push(Block::Card { items });
                inside_card = false;
                card_lines.clear();
                continue;
            }

            card_lines.push(raw);
            continue;
        }

        if raw.trim() == ":::" {
            inside_card = true;
            card_lines.clear();
            continue;
        }

        if let Some(language) = parse_fence_start(raw) {
            inside_code_fence = true;
            code_fence_lang = language;
            code_fence_lines.clear();
            continue;
        }

        blocks.push(classify_line(raw));
    }

    if inside_code_fence {
        blocks.push(code_block_from_lines(
            code_fence_lang.take(),
            &code_fence_lines,
        ));
    }

    if inside_card {
        let items = parse_card_items(&card_lines);
        blocks.push(Block::Card { items });
    }

    blocks
}

fn parse_card_items(lines: &[&str]) -> Vec<Block> {
    let mut items = Vec::new();
    let mut inside_code_fence = false;
    let mut code_fence_lang: Option<String> = None;
    let mut code_fence_lines: Vec<&str> = Vec::new();

    for raw in lines {
        if inside_code_fence {
            if is_fence_close(raw) {
                items.push(code_block_from_lines(
                    code_fence_lang.take(),
                    &code_fence_lines,
                ));
                code_fence_lines.clear();
                inside_code_fence = false;
            } else {
                code_fence_lines.push(raw);
            }
            continue;
        }

        if let Some(language) = parse_fence_start(raw) {
            inside_code_fence = true;
            code_fence_lang = language;
            code_fence_lines.clear();
            continue;
        }

        items.push(classify_line(raw));
    }

    if inside_code_fence {
        items.push(code_block_from_lines(
            code_fence_lang.take(),
            &code_fence_lines,
        ));
    }

    items
}

fn parse_fence_start(raw: &str) -> Option<Option<String>> {
    let trimmed = raw.trim();
    if !trimmed.starts_with("```") {
        return None;
    }
    let language = trimmed[3..].trim();
    if language.is_empty() {
        Some(None)
    } else {
        Some(Some(language.to_string()))
    }
}

fn is_fence_close(raw: &str) -> bool {
    let trimmed = raw.trim();
    trimmed.starts_with("```") && trimmed.chars().all(|ch| ch == '`')
}

fn code_block_from_lines(language: Option<String>, lines: &[&str]) -> Block {
    let mut code = String::new();
    for (idx, line) in lines.iter().enumerate() {
        if idx > 0 {
            code.push('\n');
        }
        code.push_str(line);
    }
    Block::CodeBlock { language, code }
}

fn classify_line(raw: &str) -> Block {
    let line = raw.trim();
    if line.is_empty() {
        return Block::Gap;
    }
    if line == "---" {
        return Block::Hr;
    }

    if let Some((level, content)) = parse_heading_line(raw) {
        let (text, tags) = split_line_tags(content);
        return Block::Heading { level, text, tags };
    }

    if let Some((alt, src, remainder)) = parse_image_line(raw) {
        let (_, tags) = split_line_tags(remainder);
        return Block::Image { alt, src, tags };
    }

    let (text, tags) = split_line_tags(raw.trim());
    Block::Paragraph { text, tags }
}

fn parse_heading_line(raw: &str) -> Option<(u8, &str)> {
    let trimmed = raw.trim_start();
    let bytes = trimmed.as_bytes();
    let mut level = 0usize;

    while level < bytes.len() && bytes[level] == b'#' && level < 4 {
        level += 1;
    }
    if level == 0 {
        return None;
    }
    if level < bytes.len() && bytes[level] == b'#' {
        return None;
    }
    if level >= bytes.len() {
        return None;
    }

    let next = trimmed[level..].chars().next()?;
    if !next.is_whitespace() {
        return None;
    }

    Some((level as u8, trimmed[level..].trim_start()))
}

fn parse_image_line(raw: &str) -> Option<(String, String, &str)> {
    let trimmed = raw.trim_start();
    if !trimmed.starts_with("![") {
        return None;
    }

    let after_open = &trimmed[2..];
    let close_bracket_rel = after_open.find(']')?;
    let close_bracket = 2 + close_bracket_rel;
    let after_bracket = &trimmed[close_bracket + 1..];
    if !after_bracket.starts_with('(') {
        return None;
    }

    let close_paren_rel = after_bracket[1..].find(')')?;
    let close_paren = close_bracket + 2 + close_paren_rel;
    let alt = trimmed[2..close_bracket].to_string();
    let src = trimmed[close_bracket + 2..close_paren].trim().to_string();
    if src.is_empty() {
        return None;
    }
    let remainder = &trimmed[close_paren + 1..];
    Some((alt, src, remainder))
}

fn split_line_tags(line: &str) -> (String, Vec<String>) {
    let mut text = line.to_string();
    let mut tags = Vec::new();

    loop {
        let trimmed_end = text.trim_end();
        if !trimmed_end.ends_with('>') {
            break;
        }

        let Some(open_idx) = trimmed_end.rfind('<') else {
            break;
        };

        let candidate = &trimmed_end[open_idx + 1..trimmed_end.len() - 1];
        if !is_tag_candidate(candidate) {
            break;
        }

        let tag = candidate.to_ascii_lowercase();
        if !is_known_tag(&tag) {
            break;
        }

        tags.insert(0, tag);

        let mut cut = open_idx;
        while cut > 0 {
            let prev = trimmed_end[..cut].chars().next_back().expect("non-empty");
            if prev.is_whitespace() {
                cut -= prev.len_utf8();
            } else {
                break;
            }
        }
        text = trimmed_end[..cut].to_string();
    }

    (text, tags)
}

fn is_tag_candidate(tag: &str) -> bool {
    if tag.is_empty() {
        return false;
    }
    if tag.starts_with('#') {
        return is_hex_color(tag);
    }
    tag.chars().all(|ch| ch.is_ascii_alphabetic())
}

fn is_known_tag(tag: &str) -> bool {
    named_color(tag).is_some()
        || is_hex_color(tag)
        || matches!(
            tag,
            "center" | "glow" | "muted" | "bold" | "round" | "button" | "spin" | "fade"
        )
}

fn is_motion_tag(tag: &str) -> bool {
    matches!(tag, "spin" | "fade")
}

fn named_color(tag: &str) -> Option<&'static str> {
    match tag {
        "blue" => Some("#1f78c8"),
        "red" => Some("#c33f49"),
        "green" => Some("#237e4b"),
        "yellow" => Some("#a57700"),
        "purple" => Some("#6d4cb3"),
        "cyan" => Some("#0b7b88"),
        "orange" => Some("#b5621e"),
        "pink" => Some("#b43f8e"),
        "white" => Some("#ffffff"),
        "black" => Some("#111111"),
        "gray" | "grey" => Some("#646d78"),
        _ => None,
    }
}

fn is_hex_color(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.first() != Some(&b'#') {
        return false;
    }
    let hex_len = bytes.len() - 1;
    if hex_len != 3 && hex_len != 6 {
        return false;
    }
    bytes[1..].iter().all(u8::is_ascii_hexdigit)
}

fn parse_inline_tags(text: &str) -> Vec<InlineNode> {
    let mut frames = vec![TagFrame {
        tag: None,
        children: Vec::new(),
        raw_open: String::new(),
    }];

    let mut i = 0usize;
    while i < text.len() {
        if text.as_bytes()[i] == b'`'
            && let Some(end_rel) = text[i + 1..].find('`')
        {
            let end = i + 1 + end_rel;
            frames
                .last_mut()
                .expect("root exists")
                .children
                .push(InlineNode::Text(text[i..=end].to_string()));
            i = end + 1;
            continue;
        }

        if text[i..].starts_with('<')
            && let Some((token_len, is_closing, tag, raw)) = parse_inline_tag_token(&text[i..])
        {
            if !is_known_tag(&tag) {
                frames
                    .last_mut()
                    .expect("root exists")
                    .children
                    .push(InlineNode::Text(raw));
                i += token_len;
                continue;
            }

            if !is_closing {
                frames.push(TagFrame {
                    tag: Some(tag),
                    children: Vec::new(),
                    raw_open: raw,
                });
                i += token_len;
                continue;
            }

            let closes_top = frames
                .last()
                .and_then(|frame| frame.tag.as_deref())
                .map(|open_tag| open_tag == tag)
                .unwrap_or(false);

            if closes_top {
                let closed = frames.pop().expect("top exists");
                frames
                    .last_mut()
                    .expect("parent exists")
                    .children
                    .push(InlineNode::Tag {
                        tag,
                        children: closed.children,
                        raw_open: closed.raw_open,
                    });
            } else {
                frames
                    .last_mut()
                    .expect("top exists")
                    .children
                    .push(InlineNode::Text(raw));
            }

            i += token_len;
            continue;
        }

        let next_lt_rel = text[i..].find('<');
        let next_tick_rel = text[i..].find('`');
        let next_rel = match (next_lt_rel, next_tick_rel) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => text.len() - i,
        };
        if next_rel == 0 {
            let ch = text[i..].chars().next().expect("char exists");
            frames
                .last_mut()
                .expect("root exists")
                .children
                .push(InlineNode::Text(ch.to_string()));
            i += ch.len_utf8();
            continue;
        }
        let next = i + next_rel;
        frames
            .last_mut()
            .expect("root exists")
            .children
            .push(InlineNode::Text(text[i..next].to_string()));
        i = next;
    }

    while frames.len() > 1 {
        let unclosed = frames.pop().expect("one frame");
        let mut literal = unclosed.raw_open;
        for child in &unclosed.children {
            literal.push_str(&render_inline_node_literal(child));
        }
        frames
            .last_mut()
            .expect("root exists")
            .children
            .push(InlineNode::Text(literal));
    }

    frames.pop().expect("root frame").children
}

fn parse_inline_tag_token(input: &str) -> Option<(usize, bool, String, String)> {
    if !input.starts_with('<') {
        return None;
    }

    let mut start = 1usize;
    let is_closing = input[start..].starts_with('/');
    if is_closing {
        start += 1;
    }

    let close_idx = input[start..].find('>')? + start;
    let candidate = &input[start..close_idx];
    if !is_tag_candidate(candidate) {
        return None;
    }

    let token_len = close_idx + 1;
    let raw = input[..token_len].to_string();
    Some((token_len, is_closing, candidate.to_ascii_lowercase(), raw))
}

fn render_inline_node_literal(node: &InlineNode) -> String {
    match node {
        InlineNode::Text(text) => text.clone(),
        InlineNode::Tag {
            raw_open, children, ..
        } => {
            let mut out = raw_open.clone();
            for child in children {
                out.push_str(&render_inline_node_literal(child));
            }
            out
        }
    }
}

fn markdown_inline(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut i = 0usize;
    let mut out = String::new();

    while i < text.len() {
        if bytes[i] == b'`'
            && let Some(end_rel) = text[i + 1..].find('`')
        {
            let end = i + 1 + end_rel;
            out.push_str("<code>");
            out.push_str(&escape_html(&text[i + 1..end]));
            out.push_str("</code>");
            i = end + 1;
            continue;
        }

        if i + 1 < text.len()
            && bytes[i] == b'*'
            && bytes[i + 1] == b'*'
            && let Some(end_rel) = text[i + 2..].find("**")
        {
            let end = i + 2 + end_rel;
            out.push_str("<strong>");
            out.push_str(&markdown_inline(&text[i + 2..end]));
            out.push_str("</strong>");
            i = end + 2;
            continue;
        }

        if bytes[i] == b'['
            && let Some(close_bracket_rel) = text[i + 1..].find(']')
        {
            let close_bracket = i + 1 + close_bracket_rel;
            if close_bracket + 1 < text.len()
                && bytes[close_bracket + 1] == b'('
                && let Some(close_paren_rel) = text[close_bracket + 2..].find(')')
            {
                let close_paren = close_bracket + 2 + close_paren_rel;
                let label = &text[i + 1..close_bracket];
                let href = text[close_bracket + 2..close_paren].trim();
                out.push_str("<a href=\"");
                out.push_str(&escape_html(href));
                out.push_str("\" target=\"_blank\" rel=\"noreferrer noopener\">");
                out.push_str(&markdown_inline(label));
                out.push_str("</a>");
                i = close_paren + 1;
                continue;
            }
        }

        let ch = text[i..].chars().next().expect("char exists");
        push_escaped_char(ch, &mut out);
        i += ch.len_utf8();
    }

    out
}

fn tags_to_attrs(tags: &[String]) -> String {
    let mut classes: Vec<&str> = Vec::new();
    let mut color: Option<String> = None;

    for tag in tags {
        if let Some(named) = named_color(tag) {
            color = Some(named.to_string());
        } else if is_hex_color(tag) {
            color = Some(tag.clone());
        } else {
            classes.push(tag.as_str());
        }
    }

    let mut attrs = String::new();
    if !classes.is_empty() {
        attrs.push_str(" class=\"");
        attrs.push_str(&escape_html(&classes.join(" ")));
        attrs.push('"');
    }
    if let Some(color) = color {
        attrs.push_str(" style=\"color:");
        attrs.push_str(&escape_html(&color));
        attrs.push_str(";\"");
    }

    attrs
}

fn render_inline_node(node: &InlineNode) -> String {
    match node {
        InlineNode::Text(text) => markdown_inline(text),
        InlineNode::Tag { tag, children, .. } => {
            let attrs = tags_to_attrs(std::slice::from_ref(tag));
            let mut inner = String::new();
            for child in children {
                inner.push_str(&render_inline_node(child));
            }
            format!("<span{attrs}>{inner}</span>")
        }
    }
}

fn render_inline_text(text: &str) -> String {
    let nodes = parse_inline_tags(text);
    let mut out = String::new();
    for node in nodes {
        out.push_str(&render_inline_node(&node));
    }
    out
}

fn render_block(block: &Block) -> String {
    match block {
        Block::Gap => "<div class=\"w-gap\" aria-hidden=\"true\"></div>".to_string(),
        Block::Hr => "<hr>".to_string(),
        Block::CodeBlock { language, code } => {
            let class_attr = if let Some(language) = language {
                format!(" class=\"language-{}\"", escape_html(language))
            } else {
                String::new()
            };
            format!("<pre><code{class_attr}>{}</code></pre>", escape_html(code))
        }
        Block::Heading { level, text, tags } => {
            let attrs = tags_to_attrs(tags);
            format!(
                "<h{level}{attrs}>{}</h{level}>",
                render_inline_text(text),
                level = level
            )
        }
        Block::Image { alt, src, tags } => {
            let attrs = tags_to_attrs(tags);
            format!(
                "<figure{attrs}><img src=\"{}\" alt=\"{}\"></figure>",
                escape_html(src),
                escape_html(alt)
            )
        }
        Block::Paragraph { text, tags } => {
            let attrs = tags_to_attrs(tags);
            format!("<p{attrs}>{}</p>", render_inline_text(text))
        }
        Block::Card { items } => {
            let mut inner = String::new();
            for item in items {
                inner.push_str(&render_block(item));
            }
            format!("<article class=\"w-card\">{inner}</article>")
        }
    }
}

fn render_blocks(blocks: &[Block]) -> String {
    let mut out = String::new();
    let mut i = 0usize;

    while i < blocks.len() {
        if matches!(blocks[i], Block::Card { .. }) {
            let mut row = Vec::new();
            while i < blocks.len() {
                if let Block::Card { .. } = &blocks[i] {
                    row.push(render_block(&blocks[i]));
                    i += 1;
                } else {
                    break;
                }
            }
            out.push_str("<section class=\"w-card-row\">");
            for card_html in row {
                out.push_str(&card_html);
            }
            out.push_str("</section>");
            continue;
        }

        if matches!(blocks[i], Block::Gap)
            && (i == 0 || matches!(blocks[i.saturating_sub(1)], Block::Gap))
        {
            i += 1;
            continue;
        }

        out.push_str(&render_block(&blocks[i]));
        i += 1;
    }

    out
}

fn collect_motion(blocks: &[Block]) -> bool {
    for block in blocks {
        match block {
            Block::Card { items } => {
                if collect_motion(items) {
                    return true;
                }
            }
            Block::Heading { tags, .. }
            | Block::Image { tags, .. }
            | Block::Paragraph { tags, .. } => {
                if tags.iter().any(|tag| is_motion_tag(tag)) {
                    return true;
                }
            }
            Block::Gap | Block::Hr | Block::CodeBlock { .. } => {}
        }
    }
    false
}

fn theme_from_meta(meta: &HashMap<String, String>) -> ResolvedTheme {
    let requested = meta
        .get("theme")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_else(|| "default".to_string());

    let base = match requested.as_str() {
        "slate" => SLATE_THEME,
        "ink" => INK_THEME,
        _ => DEFAULT_THEME,
    };

    let mut accent = meta
        .get("accent")
        .map(|value| value.to_ascii_lowercase())
        .unwrap_or_else(|| base.accent.to_string());

    if let Some(named) = named_color(&accent) {
        accent = named.to_string();
    }
    if !is_hex_color(&accent) {
        accent = base.accent.to_string();
    }

    ResolvedTheme {
        bg: base.bg,
        text: base.text,
        muted: base.muted,
        panel: base.panel,
        panel_line: base.panel_line,
        accent,
    }
}

fn generate_style(theme: &ResolvedTheme) -> String {
    format!(
        ":root{{\n  --w-bg:{};\n  --w-text:{};\n  --w-muted:{};\n  --w-panel:{};\n  --w-line:{};\n  --w-accent:{};\n}}\n\
*{{box-sizing:border-box}}\n\
body{{\n  margin:0;\n  padding:40px min(4vw,40px);\n  font:16px/1.65 \"Avenir Next\",\"Segoe UI\",sans-serif;\n  color:var(--w-text);\n  background:\n    radial-gradient(900px 400px at 95% -10%, color-mix(in srgb, var(--w-accent), white 82%) 0%, transparent 55%),\n    var(--w-bg);\n}}\n\
main{{max-width:1100px;margin:0 auto}}\n\
h1,h2,h3,h4{{line-height:1.2;margin:0.6em 0 0.45em}}\n\
h1{{font-size:clamp(1.9rem,5vw,3.2rem)}}\n\
h2{{font-size:clamp(1.5rem,3vw,2.2rem)}}\n\
h3{{font-size:1.3rem}}\n\
h4{{font-size:1.1rem}}\n\
p{{margin:0.65em 0}}\n\
a{{color:var(--w-accent)}}\n\
hr{{border:0;border-top:1px solid var(--w-line);margin:1.2rem 0}}\n\
pre{{margin:0.9rem 0;padding:12px 14px;overflow:auto;border:1px solid var(--w-line);border-radius:12px;background:color-mix(in srgb,var(--w-line),white 50%)}}\n\
figure{{margin:0.9rem 0}}\n\
img{{max-width:100%;height:auto;display:block;border-radius:12px}}\n\
code{{font-family:\"Cascadia Code\",\"Consolas\",monospace;background:color-mix(in srgb,var(--w-line),white 35%);padding:0.1rem 0.35rem;border-radius:6px}}\n\
pre code{{display:block;padding:0;border-radius:0;background:transparent;white-space:pre}}\n\
.w-gap{{height:0.8rem}}\n\
.w-card-row{{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px;margin:0.8rem 0}}\n\
.w-card{{background:var(--w-panel);border:1px solid var(--w-line);border-radius:16px;padding:14px 15px;box-shadow:0 8px 20px rgba(0,0,0,0.08)}}\n\
.center{{text-align:center}}\n\
.glow{{\n  color:color-mix(in srgb,var(--w-accent),white 16%);\n  text-shadow:\n    0 0 8px color-mix(in srgb,var(--w-accent),white 35%),\n    0 0 20px color-mix(in srgb,var(--w-accent),transparent 6%),\n    0 0 42px color-mix(in srgb,var(--w-accent),transparent 20%),\n    0 0 78px color-mix(in srgb,var(--w-accent),transparent 42%);\n  animation:w-glow-pulse 1800ms ease-in-out infinite alternate;\n}}\n\
@keyframes w-glow-pulse{{\n\
  from{{\n\
    text-shadow:\n\
      0 0 7px color-mix(in srgb,var(--w-accent),white 30%),\n\
      0 0 18px color-mix(in srgb,var(--w-accent),transparent 12%),\n\
      0 0 36px color-mix(in srgb,var(--w-accent),transparent 28%),\n\
      0 0 60px color-mix(in srgb,var(--w-accent),transparent 48%);\n\
  }}\n\
  to{{\n\
    text-shadow:\n\
      0 0 10px color-mix(in srgb,var(--w-accent),white 44%),\n\
      0 0 26px color-mix(in srgb,var(--w-accent),transparent 4%),\n\
      0 0 58px color-mix(in srgb,var(--w-accent),transparent 16%),\n\
      0 0 96px color-mix(in srgb,var(--w-accent),transparent 36%);\n\
  }}\n\
}}\n\
.muted{{color:var(--w-muted)}}\n\
.bold{{font-weight:700}}\n\
.round img,img.round{{border-radius:20px}}\n\
.button a,a.button{{display:inline-block;background:var(--w-accent);color:#fff!important;text-decoration:none;padding:0.48rem 0.82rem;border-radius:999px;font-weight:600}}\n\
.fade{{opacity:0;transform:translateY(16px)}}\n\
.spin{{display:inline-block}}",
        theme.bg, theme.text, theme.muted, theme.panel, theme.panel_line, theme.accent
    )
}

#[cfg(test)]
mod tests {
    use super::compile_weft;

    #[test]
    fn compiles_metadata_and_heading() {
        let input = "@title Example\n@desc Test page\n# Hello <center> <glow>";
        let out = compile_weft(input);
        assert!(out.html.contains("<title>Example</title>"));
        assert!(
            out.html
                .contains("meta name=\"description\" content=\"Test page\"")
        );
        assert!(out.html.contains("<h1 class=\"center glow\">Hello</h1>"));
    }

    #[test]
    fn groups_adjacent_cards_into_card_row() {
        let input = "::: \n## A\n:::\n:::\n## B\n:::".replace("::: ", ":::");
        let out = compile_weft(&input);
        assert!(out.html.contains("<section class=\"w-card-row\">"));
        assert_eq!(out.html.matches("<article class=\"w-card\">").count(), 2);
    }

    #[test]
    fn unknown_inline_tags_render_literally() {
        let input = "Hello <unknown>world</unknown>";
        let out = compile_weft(input);
        assert!(out.html.contains("&lt;unknown&gt;world&lt;/unknown&gt;"));
    }

    #[test]
    fn unclosed_inline_tags_render_literally() {
        let input = "This <glow>word";
        let out = compile_weft(input);
        assert!(out.html.contains("&lt;glow&gt;word"));
    }

    #[test]
    fn injects_motion_script_only_when_needed() {
        let with_motion = compile_weft("This line fades <fade>");
        assert!(with_motion.with_motion);
        assert!(with_motion.html.contains("<script>"));

        let without_motion = compile_weft("This line does not move");
        assert!(!without_motion.with_motion);
        assert!(!without_motion.html.contains("<script>"));
    }

    #[test]
    fn inline_code_keeps_weft_tags_literal() {
        let out = compile_weft("Use `<glow>literal</glow>` inline.");
        assert!(
            out.html
                .contains("<code>&lt;glow&gt;literal&lt;/glow&gt;</code>")
        );
        assert!(!out.html.contains("<span class=\"glow\">literal</span>"));
    }

    #[test]
    fn fenced_code_block_keeps_weft_syntax_literal() {
        let input = "```weft\n# Demo <glow>\nThis <red>line</red>\n```\nAfter";
        let out = compile_weft(input);
        assert!(out.html.contains("<pre><code class=\"language-weft\">"));
        assert!(out.html.contains("# Demo &lt;glow&gt;"));
        assert!(out.html.contains("This &lt;red&gt;line&lt;/red&gt;"));
        assert!(!out.html.contains("<h1"));
    }

    #[test]
    fn code_fence_inside_card_does_not_break_card_parsing() {
        let input = ":::\n```weft\n:::\n```\n:::";
        let out = compile_weft(input);
        assert_eq!(out.html.matches("<article class=\"w-card\">").count(), 1);
        assert!(out.html.contains("<pre><code class=\"language-weft\">:::"));
    }
}
