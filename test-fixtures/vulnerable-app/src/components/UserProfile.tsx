import React from 'react';

interface Props {
  bio: string;
  username: string;
}

// VULNERABILITY: dangerouslySetInnerHTML without sanitization
export function UserProfile({ bio, username }: Props) {
  return (
    <div>
      <h1>{username}</h1>
      {/* VULNERABILITY: XSS via dangerouslySetInnerHTML */}
      <div dangerouslySetInnerHTML={{ __html: bio }} />
    </div>
  );
}

// VULNERABILITY: innerHTML assignment
export function renderContent(element: HTMLElement, content: string) {
  element.innerHTML = content;
}

// VULNERABILITY: document.write
export function injectScript(url: string) {
  document.write(`<script src="${url}"></script>`);
}

// SECURE: Using textContent instead
export function renderTextContent(element: HTMLElement, text: string) {
  element.textContent = text;
}
