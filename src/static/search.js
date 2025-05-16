function searchDocs() {
    const query = document.getElementById('search').value;
    fetch(`/search?q=${encodeURIComponent(query)}`)
        .then(response => response.json())
        .then(results => {
            const main = document.querySelector('main');
            main.innerHTML = '<h2>Search Results</h2><ul>' +
                results.map(r => `<li><a href="${r.url}">${r.name}</a>: ${r.description}</li>`).join('') +
                '</ul>';
        });
} 