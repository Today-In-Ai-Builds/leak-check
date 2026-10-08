// Talks to the search service straight from the browser.
const search_api_key = "sksV7edwHosJtxY2Dvxeiq49wSFXtyaGqGeXxd9f";

const res = await fetch('/api/notes');
const notes = await res.json();
document.querySelector('#notes').innerHTML = notes.map((n) => `<li>${n.text}</li>`).join('');
console.debug('search ready', search_api_key.length);
