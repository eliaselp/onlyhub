let b=document.getElementById("enviar")
if(b){
  b.addEventListener("click", () => {
    const form = document.getElementById("buscar");
    form.submit();
  });
}

let a=document.getElementById("send")
if(a){
  a.addEventListener("click", () => {
    var form = document.getElementById("mensaje");
    form.submit();
  });
}

c=document.getElementById("chatear")
if(c){
  c.addEventListener("click", function (event) {
    let contenedor = document.getElementById("chats");
    let boton_info = document.getElementById("info");
    let public = document.getElementById("publicaciones");
    public.classList.replace("d-block", "d-none");
    contenedor.classList.replace("d-none", "d-block");
    this.classList.add("d-none");
    boton_info.classList.add("d-none");
    boton_block = document.getElementById("block");
    boton_block.classList.replace("d-none", "d-block");
  });
}

d=document.getElementById("block")
if(d){
  d.addEventListener("click", function (event) {
    event.preventDefault();

    let contenedor = document.getElementById("chats");
    let boton_info = document.getElementById("info");
    let boton_chat = document.getElementById("chatear");
    let public = document.getElementById("publicaciones");
    contenedor.classList.replace("d-block", "d-none");
    public.classList.replace("d-none", "d-block");
    this.classList.replace("d-block", "d-none");
    boton_chat.classList.replace("d-none", "d-block");
    boton_info.classList.replace("d-none", "d-block");
  });
}
e=document.getElementById("ver_grupos")
if(e){
    e.addEventListener("click", function () {
        let contenedor = document.getElementById('contenedor_modal_contacto');
        contenedor.classList.add('d-none');
        contenedor = document.getElementById("contenedor_modal_grupo");
        if (contenedor && contenedor.classList.contains("d-none")) {
            contenedor.classList.remove("d-none");
        }
    });
}

f=document.getElementById("ver_contactos")
if(f){
    f.addEventListener("click", function () {
        let contenedor = document.getElementById('contenedor_modal_grupo');
        contenedor.classList.add('d-none');
        contenedor = document.getElementById("contenedor_modal_contacto");
        if (contenedor && contenedor.classList.contains("d-none")) {
            contenedor.classList.remove("d-none");
        }
    });
}

document.addEventListener("DOMContentLoaded", function () {
    const contenedor = document.getElementById("container_public");
    const svgIzquierda = document.getElementById("svg-izquierda");
    const svgDerecha = document.getElementById("svg-derecha");
    if(contenedor && svgIzquierda && svgDerecha){
        const scrollStep = contenedor.clientWidth; // Desplazamiento equivalente al ancho de una imagen

        if (contenedor.scrollWidth > contenedor.clientWidth) {
            svgDerecha.classList.remove("d-none");
            svgIzquierda.classList.remove("d-none");
        } else {
            svgDerecha.classList.add("d-none");
            svgIzquierda.classList.add("d-none");
        }
  
  
  
        svgIzquierda.addEventListener("click", function () {
            const newScrollLeft = Math.max(0, contenedor.scrollLeft - scrollStep);
            animarScroll(contenedor.scrollLeft, newScrollLeft);
        });
    
  
        svgDerecha.addEventListener("click", function () {
            const newScrollLeft = Math.min(
                contenedor.scrollLeft + scrollStep,
                contenedor.scrollWidth - contenedor.clientWidth
            );
            animarScroll(contenedor.scrollLeft, newScrollLeft);
        });
  

        function animarScroll(start, end) {
            const duration = 1000; // Duración de la animación en milisegundos
            const startTime = performance.now();
            const elementos = contenedor.querySelectorAll("#poster");
            const intervalo = duration / elementos.length; // Intervalo entre cada imagen

            elementos.forEach((elemento, index) => {
                setTimeout(() => {
                    elemento.classList.add("hover-effect");
                    setTimeout(() => {
                        elemento.classList.remove("hover-effect");
                    }, 300); // Después de 1 segundo, eliminar la clase de efecto de hover
                }, index * intervalo); // Aplicar el efecto de hover en intervalos
            });

            function step(timestamp) {
                const elapsed = timestamp - startTime;
                const progress = Math.min(elapsed / duration, 1);
                contenedor.scrollLeft = start + (end - start) * progress;

                if (progress < 1) {
                requestAnimationFrame(step);
                }
            }

            requestAnimationFrame(step);
            // Agregar clase de efecto de hover a los elementos durante 1 segundo
        }
    }
    
    document.addEventListener('click', function (e) {
        if (e.target.classList.contains('btn-eliminar-publicacion')) {
            if (confirm("¿Estás seguro de que deseas eliminar esta publicación?")) {
                id_form="#"+e.target.id
                document.getElementById(id_form).submit()
            }
        }
    });
    
    document.addEventListener('click', function (e) {
        if (e.target.classList.contains('btn_eliminar_publicacion_grupal')) {
            if (confirm("¿Estás seguro de que deseas eliminar esta publicación?")) {
                id_form="#"+e.target.id
                document.getElementById(id_form).submit()
            }
        }
    });
    btn_get_config_grupo=document.getElementById('btn-get-config-grupo')
    if(btn_get_config_grupo){
        btn_get_config_grupo.addEventListener("click",function(e){
            //quitar
            let contenedor = document.getElementById('btn-get-config-grupo');
            contenedor.classList.add('d-none');
            contenedor = document.getElementById('contenedor-publicaciones-grupales');
            contenedor.classList.add('d-none');
            contenedor = document.getElementById('info_grupo');
            contenedor.classList.add('d-none');
            
            //mostrar
            contenedor = document.getElementById("btn-get-blog-grupo");
            if (contenedor && contenedor.classList.contains("d-none")) {
                contenedor.classList.remove("d-none");
            }
            contenedor = document.getElementById("contenedor-configuracion-grupo");
            if (contenedor && contenedor.classList.contains("d-none")) {
                contenedor.classList.remove("d-none");
            }
        })  
    }
    btn_get_blog_grupo=document.getElementById("btn-get-blog-grupo")
    if(btn_get_blog_grupo){
        btn_get_blog_grupo.addEventListener("click",function(e){
            let contenedor = document.getElementById('contenedor-configuracion-grupo');
            contenedor.classList.add('d-none');
            contenedor = document.getElementById('btn-get-blog-grupo');
            contenedor.classList.add('d-none');
            
            contenedor = document.getElementById("btn-get-config-grupo");
            if (contenedor && contenedor.classList.contains("d-none")) {
                contenedor.classList.remove("d-none");
            } 
            contenedor = document.getElementById("contenedor-publicaciones-grupales");
            if (contenedor && contenedor.classList.contains("d-none")) {
                contenedor.classList.remove("d-none");
            } 
            contenedor = document.getElementById("info_grupo");
            if (contenedor && contenedor.classList.contains("d-none")) {
                contenedor.classList.remove("d-none");
            } 
        })
    }
    
    
});

