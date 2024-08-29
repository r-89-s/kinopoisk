const stars = document.querySelectorAll('.comment-stars>img')
function rateFilm(rate){
    for(let i = 0; i < stars.length; i++){
        stars[i].classList.remove('active-star')
    }
    for(let i = 0; i < rate; i++){
        stars[i].classList.add('active-star')
    }
}

function sendRate(e){
    e.preventDefault()
    const activeStars = document.querySelectorAll('.active-star')
    const commentText = document.querySelector('#comment-text').value
    const author = document.querySelector('#comment_author').value
    const film = document.querySelector('#comment_film').value

    if(activeStars.length > 0){
        axios.post('/api/rate', {rate: activeStars.length, text: commentText, authorId: author, filmId: film}).then(data => {
            if(data.data){
                location.reload()
            }
        })
    }
}