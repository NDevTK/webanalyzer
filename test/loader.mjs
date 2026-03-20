/* loader.mjs — File loading for the test suite via fetch.
   Test files are served by the test runner at /test/ paths. */

export function readTestFile(relativePath) {
  const xhr = new XMLHttpRequest();
  xhr.open('GET', `/test/${relativePath}`, false);
  xhr.send();
  if (xhr.status === 200) return xhr.responseText;
  throw new Error(`Failed to load /test/${relativePath}: ${xhr.status}`);
}

export function tryReadTestFile(relativePath) {
  try {
    const xhr = new XMLHttpRequest();
    xhr.open('GET', `/test/${relativePath}`, false);
    xhr.send();
    if (xhr.status === 200) return xhr.responseText;
    return null;
  } catch { return null; }
}

export function listTestDir(relativePath) {
  const xhr = new XMLHttpRequest();
  xhr.open('GET', `/test/${relativePath}/?list`, false);
  xhr.send();
  if (xhr.status === 200) return JSON.parse(xhr.responseText);
  return [];
}
