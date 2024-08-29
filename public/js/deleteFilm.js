function deleteFilms(id, authorID){
    axios.delete(`/api/films/${id}`).then(data => {
        if(data.status == 200){
            location.replace(`/admin/${authorID}`)
        }else if(data.status == 404){
            location.replace(`/not-found`)
        }
    })
    console.log(id, authorID)
}