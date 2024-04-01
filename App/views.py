from django.shortcuts import render,redirect
from django.views.generic import View
from django.contrib.auth import logout
from django.core.mail import send_mail
import uuid
import base64
import re
from django.core.files.images import get_image_dimensions
from datetime import datetime
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login as auth_login
from django.contrib.auth.hashers import check_password
from django.views.decorators.cache import never_cache


from App.models import Usuario,ResetPass,Contacto,Publicacion_Personal,Grupo,Grupo_Member,Publicacion_Grupal
from App.models import Solicitud,Like_Publicacion_Personal,Like_Publicacion_Grupal
from LinkWolf.settings import EMAIL_HOST_USER,ENVIO_EMAIL

# Create your views here.

# Para cifrar (codificar) un string a base64
def cifrar_base64(input_string):
    input_bytes = input_string.encode('utf-8')
    base64_bytes = base64.b64encode(input_bytes)
    base64_string = base64_bytes.decode('utf-8')
    return base64_string

# Para descifrar (decodificar) un string en base64
def descifrar_base64(base64_string):
    output_bytes = base64.b64decode(base64_string)
    output_string = output_bytes.decode('utf-8')
    return output_string

#Obtener lista de contactos de un usuario dado
def getContactos(username):
    usuario=Usuario.objects.get(username=username)
    contactos=list(Contacto.objects.filter(Usuario_ID=usuario))
    lista=[]
    for actual in contactos:
        lista.append(actual.ContactoUser_ID)
    return lista

def validar_telefono(numero):
    # Esta expresión regular valida formatos comunes de números telefónicos
    patron = re.compile(r'^(\+\d{1,3})?\s?(\d{2,3})?[-.\s]?\d{3}[-.\s]?\d{4}$')
    return patron.match(numero) is not None


def validar_imagen(archivo):
    try:
        w, h = get_image_dimensions(archivo)
        if w == 0 or h == 0:
            return False
    except Exception as e:
        return False
    return True

def get_foto_perfil(username):
    usuario = Usuario.objects.get(username=username)
    url_foto_perfil = usuario.Foto_Perfil.url if usuario.Foto_Perfil else None
    return url_foto_perfil

def get_foto_grupo(grupo):
    return grupo.imagen.url if grupo.imagen else None

def get_foto_publicacion_personal(publicacion):
    url_imagen = publicacion.imagen.url if publicacion.imagen else None
    return url_imagen

def get_publicaciones_personales(username,mi):
    usuario = Usuario.objects.get(username=username)
    contexto=list()#<dict>("like_mio", "publicacion")
    publicaciones=list(Publicacion_Personal.objects.filter(UsuarioID=usuario).order_by('-id'))
    for p in publicaciones:
        if(Like_Publicacion_Personal.objects.filter(Publicacion_Personal_ID=p,Usuario_ID=mi).exists()):
            contexto.append({"like_mio":True,"p":p})
        else:
            contexto.append({"like_mio":False,"p":p})
    return contexto

def get_publicaciones_grupales(grupo_id,usuario):
    grupo=list(Grupo.objects.filter(id=grupo_id))
    if(grupo.__len__()>0):
        grupo=grupo[0]
        membresia=list(Grupo_Member.objects.filter(Usuario_ID=usuario,Grupo_ID=grupo))
        if(membresia.__len__()>0):
            Admin=membresia[0].Admin
            Publicaciones=list(Publicacion_Grupal.objects.filter(Grupo_ID=grupo).order_by('-id'))
            pp=list()#<dict>("like_mio", "publicacion")
            for p in Publicaciones:
                if(Like_Publicacion_Grupal.objects.filter(Publicacion_Grupal_ID=p,GrupoMember_ID=membresia[0]).exists()):
                    pp.append({"like_mio":True,"p":p})
                else:
                    pp.append({"like_mio":False,"p":p})
            contexto={"Admin":Admin,"Miembro":True,"grupo":grupo,"Publicaciones":pp}
            return contexto
        else:
            solicitud=list(Solicitud.objects.filter(Grupo_ID=grupo,Usuario_ID=usuario))
            Publicaciones=list(Publicacion_Grupal.objects.filter(Grupo_ID=grupo).order_by('-id'))
            if(solicitud.__len__()>0):
                return {"Admin":False,"Miembro":False,"Solicitud":True,"grupo":grupo,"Publicaciones":Publicaciones}
            else:
                return {"Admin":False,"Miembro":False,"Solicitud":False,"grupo":grupo,"Publicaciones":Publicaciones}
    else:
        return None

def get_solicitudes_grupo(grupo):
    solicitudes=list(Solicitud.objects.filter(Grupo_ID=grupo))
    return solicitudes

def get_miembros_grupo(grupo):
    return list(Grupo_Member.objects.filter(Grupo_ID=grupo).order_by('-Admin'))

def busqueda_contacto(username):
    lista = list(Usuario.objects.filter(username__icontains=username))
    return lista
            
def busqueda_grupo(group_name,usuario):
    #list<dict>("Admin","Miembro", "Grupo")
    grupos=list(Grupo.objects.filter(Nombre_Grupo__icontains=group_name))
    contexto_busqueda=list()
    for g in grupos:
        membresia=list(Grupo_Member.objects.filter(Usuario_ID=usuario,Grupo_ID=g))
        Admin=False
        Miembro=False
        if(membresia.__len__()>0):
            membresia=membresia[0]
            Miembro=True
            Admin=membresia.Admin
        contexto_busqueda.append({"Admin":Admin,"Miembro":Miembro,"Grupo":g})
    return contexto_busqueda


def get_grupos_usuario(usuario):
    membresia=list(Grupo_Member.objects.filter(Usuario_ID=usuario))
    contexto=list()#<dic>"Admin","Grupo"
    for m in membresia:
        admin=m.Admin
        dic={"Admin":admin,"Grupo":m.Grupo_ID}
        contexto.append(dic)
    return contexto
    
def nav_bar_top(usuario):
    publicaciones=list(Publicacion_Personal.objects.filter(UsuarioID=usuario))
    cont=0
    cont_post=publicaciones.__len__()
    for pp in publicaciones:
        likes=list(Like_Publicacion_Personal.objects.filter(Publicacion_Personal_ID=pp))
        cont+=likes.__len__()
    membresias=list(Grupo_Member.objects.filter(Usuario_ID=usuario))
    for m in membresias:
        publicaciones=list(Publicacion_Grupal.objects.filter(Grupo_Member_ID=m))
        cont_post+=publicaciones.__len__()
        for pg in publicaciones:
            likes=list(Like_Publicacion_Grupal.objects.filter(Publicacion_Grupal_ID=pg))
            cont+=likes.__len__()
    Cant_users=list(Usuario.objects.all()).__len__()
    try:
        popularidad=int((cont/(cont_post*Cant_users))*100)
    except Exception as e:
        popularidad=0
    return {"cant_likes":cont,"cant_post":cont_post,"popularidad":popularidad}


@never_cache
def e404(request,exception):
    return render(request,"404.html",status=404)

@never_cache
def login(request):
    if request.user.is_authenticated:
        return redirect("index")
    else:
        if(request.method=="POST"):
            if(request.POST.get('opc')=="forget-pass"):
                return redirect("forget")
            else:
                email = request.POST.get('email')
                password = request.POST.get('password')
                if(email=="" or password==""):
                    return render(request,"error_login.html",{"mensaje":"Todos los campos son obligatorios","email":email,"password":password})
                else:
                    try:
                        user = User.objects.get(email=email)
                        username=user.username
                        user = authenticate(request,username=username, password=password)
                        
                        auth_login(request,user)
                        token=str(uuid.uuid4())
                        dataUser=Usuario.objects.get(username=username)
                        dataUser.strToken=token
                        dataUser.save()

                        if(ENVIO_EMAIL==True):
                            asunto = 'Alerta de inicio de sesión a LinkWolf'
                            mensaje = f'Hola {username}, Gracias por utilizar nuestra aplicación. A continuación, te proporcionamos el código de confirmación de acceso:\n\n {token}\n\n Por favor, introdúcelo en la aplicación para verificar tu acceso. Si no intentaste acceder, ignora este mensaje.'
                            remitente = EMAIL_HOST_USER # El mismo valor que en settings.py
                            destinatarios = [email] # Una lista con el email del usuario registrado
                            send_mail(asunto, mensaje, remitente, destinatarios)

                        return redirect("index")
                          
                    except Exception as e:
                        if("'AnonymousUser' object has no attribute '_meta'" in str(e)):
                            user = User.objects.get(email=email)
                            if(user.is_active==1):
                                return render(request,"error_login.html",{"mensaje":"Correo o Password Incorrecto","email":email,"password":password})    
                            else:
                                return render(request,"error_login.html",{"mensaje":"Su cuenta ha sido baneada temporalmente","email":email,"password":password})
                        elif("User matching query does not exist." in str(e)):
                            return render(request,"error_login.html",{"mensaje":"Correo o Password Incorrecto","email":email,"password":password})   
                        return render(request,"error_login.html",{"mensaje":str(e),"email":email,"password":password})
        return render(request,"login.html",{"email":"","password":""})


@never_cache
def forget_pass(request):
    if request.user.is_authenticated:
        return redirect("index")
    
    if (request.method=="POST"):
        if(request.POST.get("opc")=="envio-token"):          
            try:
                email=descifrar_base64(request.POST.get("email"))
                tocken_post=request.POST.get("token").strip()
                username=User.objects.get(email=email)
                usuario=Usuario.objects.get(username=username)
                reset_db=ResetPass.objects.get(UsuarioID=usuario)
                tocken_db=reset_db.strToken

                if(tocken_post==tocken_db):
                    return render(request,"cambiar_clave.html",{"email":cifrar_base64(email),"tocken":cifrar_base64(tocken_db)})
                else:
                    aux=reset_db.cant_intentos
                    aux-=1
                    if(aux>0):
                        reset_db.cant_intentos=aux
                        reset_db.save()
                        return render(request,"error_verificacion_email_forget.html",{"mensaje":f"Tocken Invalido, le quedan {aux} intentos","email":cifrar_base64(email)})
                    else:
                        reset_db.delete()
                        return redirect("login")
            except Exception as e:
                if("ResetPass matching query does not exist" in str(e)):
                    return redirect("login")
                return render(request,"error_verificacion_email_forget.html",{"mensaje":str(e),"username":cifrar_base64(username)})
        
        elif(request.POST.get("opc")=="send-email-forget"):

            email=request.POST.get("email")
            usuario=list(User.objects.filter(email=email))
            if(usuario.__len__()>0):
                token=str(uuid.uuid4())

                username=usuario[0].username
                usuario=list(Usuario.objects.filter(username=username))[0]
                reset=list(ResetPass.objects.filter(UsuarioID=usuario))
                if(reset.__len__()==0):
                    reset=ResetPass(UsuarioID=usuario,strToken=token,cant_intentos=3)
                    reset.save()
                else:
                    reset=reset[0]
                    reset.strToken=token
                    reset.cant_intentos=3
                    reset.save()
                    

                if(ENVIO_EMAIL==True):
                    asunto = 'Alerta de cambio de clave de LinkWolf'
                    mensaje = f'Hola {username},\nHemos recibido una solicitud para restablecer la contraseña de su cuenta. Si no has realizado esta solicitud, por favor ignora este mensaje.\n\nPara completar este proceso su codigo de verificacion es el siguiente:\n\n {token}'
                    remitente = EMAIL_HOST_USER # El mismo valor que en settings.py
                    destinatarios = [email] # Una lista con el email del usuario registrado
                    send_mail(asunto, mensaje, remitente, destinatarios)

                return render(request,"verificar_email_forget.html",{"email":cifrar_base64(email)})
            else:
                return render(request,"error_forget_pass.html",{"mensaje":"Correo electronico no registrado","email":email})
        

        elif(request.POST.get("opc")=="cambiar-clave"):
            email=descifrar_base64(request.POST.get("email"))
            tocken=descifrar_base64(request.POST.get("tocken"))

            password1=request.POST.get("password1")
            password2=request.POST.get("password2")



            if(password1==password2):
                # Verificar longitud mínima de 8 caracteres
                if len(password1) < 8:
                    return render(request,"error_cambiar_clave.html",{"mensaje":"Contraseña muy corta","email":cifrar_base64(email),"tocken":cifrar_base64(tocken)})
                    
                
                # Verificar si contiene al menos un número
                if not any(char.isdigit() for char in password1):
                    render(request,"error_cambiar_clave.html",{"mensaje":"Las contraseñas deben contener numero","email":cifrar_base64(email),"tocken":cifrar_base64(tocken)})
                
                # Verificar si contiene al menos una letra minúscula y una mayúscula
                if not any(char.islower() for char in password1) or not any(char.isupper() for char in password1):
                    return render(request,"error_cambiar_clave.html",{"mensaje":"La contraseña debe tener mayúsculas y minúsculas","email":cifrar_base64(email),"tocken":cifrar_base64(tocken)})
                
                
                
                # Verificar si contiene al menos un caracter especial
                caracteres_especiales = set("[!@#$%^&*()_+-=[]{}\|;:,.<>\?]")
                if(any(caracter in caracteres_especiales for caracter in password1)==False):
                    return render(request,"error_cambiar_clave.html",{"mensaje":"La contraseña debe tener caracteres especiales","email":cifrar_base64(email),"tocken":cifrar_base64(tocken)})

                
                try:
                    usuario=list(User.objects.filter(email=email))
                    if(usuario.__len__()>0):
                        usuario=usuario[0]
                        username=usuario.username
                        usuarioMio=Usuario.objects.get(username=username)
                        resetpass=list(ResetPass.objects.filter(UsuarioID=usuarioMio))
                        if(resetpass.__len__()>0):
                            if(resetpass[0].strToken==tocken):
                                usuario.set_password(password1)
                                usuario.save()

                                user = authenticate(request,username=username, password=password1)
                                auth_login(request,user)

                                usuario = Usuario.objects.get(username=username)
                                usuario.tocken2FA=True
                                usuario.save()
                                resetpass=ResetPass.objects.get(UsuarioID=usuarioMio)
                                resetpass.delete()
                                return redirect("index")        
                            else:
                                return render(request,"error_cambiar_clave.html",{"mensaje":"TOCKEN DE SEGURIDAD INVALIDO","email":cifrar_base64(email),"tocken":cifrar_base64(tocken)})    
                        else:
                            return render(request,"error_cambiar_clave.html",{"mensaje":"ERROR AL CAMBIAR SU CLAVE","email":cifrar_base64(email),"tocken":cifrar_base64(tocken)})

                    
                except Exception as e:
                    if("'AnonymousUser' object has no attribute '_meta'" in str(e)):
                        user = User.objects.get(username=username)
                        if(user.is_active==0):
                            return redirect("login")
                        else:
                            return render(request,"error_cambiar_clave.html",{"mensaje":str(e),"email":cifrar_base64(email),"tocken":cifrar_base64(tocken)})                                                    
                    else:
                        return render(request,"error_cambiar_clave.html",{"mensaje":str(e),"email":cifrar_base64(email),"tocken":cifrar_base64(tocken)})                        
            else:
                return render(request,"error_cambiar_clave.html",{"mensaje":"Las claves no son iguales","email":cifrar_base64(email),"tocken":cifrar_base64(tocken)})
    else:
        return render(request,"forget_pass.html",{"email":""})

@never_cache
def verificacion(request):
    if request.user.is_authenticated:
        if(request.method=="POST"):
            opc=request.POST.get("opc")
            username=request.user
            if(opc=="cerrar-sesion"):
                user_logued=Usuario.objects.get(username=username)
                user_logued.tocken2FA=False
                user_logued.save()
                logout(request)
                return redirect("login")
            elif(opc=="envio-token"):
                Post_token=str(request.POST.get("token")).strip()
                user_logued=Usuario.objects.get(username=username)
                token=user_logued.strToken
                if(Post_token==token):    
                    user_logued.strToken=""
                    user_logued.tocken2FA=True
                    user_logued.save()
                    return redirect("index")
                else:
                    return render(request,"error_verificacion.html",{"mensaje":"Error, token invalido"})
                
        return render(request,"verificacion_email.html")
    else:
        return redirect("login")

@never_cache
def register(request):
    if request.user.is_authenticated:
        return redirect("index")
    else:
        if request.method == 'POST':
            username = request.POST.get('username')
            email = request.POST.get('email')
            password1 = request.POST.get('password1')
            password2 = request.POST.get('password2')
            
            if not username or not email or not password1 or not password2:
                return render(request,"error_Register.html",{'mensaje':'Por favor, complete todos los campos.'})
            
            

            ####################################################################################################################
            Valid_username=True
            
            # Verificar si la cadena contiene caracteres especiales
            caracteres_especiales = set("!@#$%^&*()_+-=[]{}|;:,.<>?")
            if any(char in caracteres_especiales for char in username):
                Valid_username=False
            
            if(Valid_username==False):
                return render(request,"error_Register.html",{'mensaje':'Nombre de usuario invalido'})
            
            ####################################################################################################################

            allowed_domains = ['gmail.com','emailabox.pro']
            domain = email.split('@')[-1]
            dominio_permitido=False
            if domain in allowed_domains:
                dominio_permitido=True
            else:
                dominio_permitido=False

            if(dominio_permitido==False):
                return render(request,"error_Register.html",{'mensaje':'Solo se admiten correos de Gmail'})

            ####################################################################################################################
            if password1 != password2:
                #messages.error(request, 'Las contraseñas no coinciden.')
                return render(request,"error_Register.html",{'mensaje':'Las contraseñas no coinciden'})

            ####################################################################################################################
            # Verificar longitud mínima de 8 caracteres
            if len(password1) < 8:
                return render(request,"error_Register.html",{'mensaje':'Contraseña muy corta'})
            
            # Verificar si contiene al menos un número
            if not any(char.isdigit() for char in password1):
                return render(request,"error_Register.html",{'mensaje':'Las contraseñas debe contener numeros'})
            
            # Verificar si contiene al menos una letra minúscula y una mayúscula
            if not any(char.islower() for char in password1) or not any(char.isupper() for char in password1):
                return render(request,"error_Register.html",{'mensaje':'Las contraseñas debe tener mayúsculas y minúsculas'})
            
            
            
            # Verificar si contiene al menos un caracter especial
            caracteres_especiales = set("[!@#$%^&*()_+-=[]{}\|;:,.<>\?]")
            if(any(caracter in caracteres_especiales for caracter in password1)==False):
                return render(request,"error_Register.html",{'mensaje':'Las contraseñas debe tener caracteres especiales'})
            
            ####################################################################################################################

            # Crea el usuario
            try:
                user = User.objects.create_user(username, email, password1)
                user  = authenticate(request,username=username, password=password1)
                if user is not None:
                    u = Usuario(username=username,Info="I like LinkWolf",tocken2FA=False,online=False,Nombres="",Apellidos="",Telefono="",Pais="",Ciudad="")
                    token=str(uuid.uuid4())
                    u.strToken=token
                    u.save()

                    if(ENVIO_EMAIL==True):
                        asunto = 'Bienvenido a LinkWolf'
                        mensaje = f'Hola {username}, Gracias por registrarse en nuestra aplicación. Para completar el proceso de registro su codigo de verificacion es el siguiente:\n\n {token}'
                        remitente = EMAIL_HOST_USER # El mismo valor que en settings.py
                        destinatarios = [email] # Una lista con el email del usuario registrado
                        send_mail(asunto, mensaje, remitente, destinatarios)
                        
                    auth_login(request,user)
                    return redirect("index")
                else:
                    return render(request,"error_Register.html",{'mensaje':'No le sale de la pinga autenticar'})
                            
            except Exception as e:
                error=str(e)
                mensaje=""
                if("App_usuario.username" in error or "auth_user.username" in error):
                    mensaje="Error. El Usuario ya esta Registrado"
                elif("App_usuario.email" in error):
                    mensaje="Error. Este Email ya esta en uso"
                else:
                    mensaje=e.__str__()
                return render(request,"error_Register.html",{'mensaje':mensaje})
        else:
            return render(request, 'register.html')  # Renderiza la plantilla de registro

@never_cache
def index(request):
    if request.user.is_authenticated:
        u = Usuario.objects.get(username=request.user.username)
        if(u.tocken2FA==False):
            return redirect("verificacion")
        else:
            if(u.online==False):
                u.online=True
                u.save()
            if(request.method=="POST"):
                opc=request.POST.get("opc")
                if(opc=="cerrar-sesion"):
                    user_logued=Usuario.objects.get(username=u.username)
                    user_logued.tocken2FA=False
                    user_logued.online=False
                    user_logued.save()
                    logout(request)
                    return redirect("login")    
                elif(opc=="solicitud-perfil-propio"):
                    return render(request,"perfil_propio.html",{
                        "usuario":u,
                        "contactos":getContactos(u.username),
                        "url_foto_perfil":get_foto_perfil(request.user.username),
                        "publicaciones":get_publicaciones_personales(u,u),
                        "Mostrar_Contactos":True,
                        "grupos":get_grupos_usuario(u),
                        "nav_top":nav_bar_top(u),
                    }) 
                elif(opc=="solicitud-perfil-usuario"):
                    quien=request.POST.get("listacontacto-username-post")
                    if(quien==request.user.username):
                        return render(request,"perfil_propio.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "publicaciones":get_publicaciones_personales(u,u),
                            "Mostrar_Contactos":True,
                            "grupos":get_grupos_usuario(u),
                            "nav_top":nav_bar_top(u),
                        })                             
                    return render(request,"perfil_usuario.html",
                            {"usuario":u,
                             "contactos":getContactos(u.username),
                             "url_foto_perfil":get_foto_perfil(request.user.username),
                             "quien":Usuario.objects.get(username=quien),
                             "publicaciones":get_publicaciones_personales(quien,u),
                             "Mostrar_Contactos":True,
                             "grupos":get_grupos_usuario(u),
                             "nav_top":nav_bar_top(u),
                             })
                elif(opc=="configuracion"):
                    return render(request,"configuracion_usuario.html",{
                        "usuario":u,"contactos":getContactos(u.username),
                        "url_foto_perfil":get_foto_perfil(request.user.username),
                        "Mostrar_Contactos":True,
                        "nav_top":nav_bar_top(u),
                        "grupos":get_grupos_usuario(u)
                    })           
                elif(opc=="config-info"):
                    try:
                        Nuevo_Nombre=request.POST.get("input-nombre")
                        Nuevo_Apellido=request.POST.get("input-apellido")
                        Nuevo_Telefono=request.POST.get("input-telefono")
                        Nuevo_Pais=request.POST.get("input-pais")
                        Nuevo_Ciudad=request.POST.get("input-ciudad")
                        Nueva_Info=request.POST.get("input-info")
                        Nueva_Fecha_Nacimiento=str(request.POST.get("input-fecha-nacimiento"))
                        Nuevo_username=request.POST.get("input-username")
                        if(Nuevo_Telefono!=""):
                            if(not validar_telefono(Nuevo_Telefono)):
                                return render(request,"configuracion_usuario.html",{
                                    "usuario":u,"contactos":getContactos(u.username),
                                    "Alerta":"Numero telefonico invalido",
                                    "url_foto_perfil":get_foto_perfil(request.user.username),
                                    "Mostrar_Contactos":True,
                                    "nav_top":nav_bar_top(u),
                                    "grupos":get_grupos_usuario(u)
                                })
                        if(Nuevo_username):        
                            if(Nuevo_username!=u.username):
                                # Verificar si la cadena contiene caracteres especiales
                                caracteres_especiales = set("!@#$%^&*()_+-=[]{}|;:,.<>?")
                                if any(char in caracteres_especiales for char in Nuevo_username):
                                    return render(request,"configuracion_usuario.html",{
                                        "usuario":u,"contactos":getContactos(u.username),
                                        "Alerta":"El nombre de usuario no debe contener caracteres especiales",
                                        "url_foto_perfil":get_foto_perfil(request.user.username),
                                        "Mostrar_Contactos":True,
                                        "nav_top":nav_bar_top(u),
                                        "grupos":get_grupos_usuario(u)
                                    })                      
                                if(User.objects.filter(username=Nuevo_username).exists()):
                                    return render(request,"configuracion_usuario.html",{
                                        "usuario":u,"contactos":getContactos(u.username),
                                        "Alerta":"Este nombre de usuario ya esta en uso",
                                        "url_foto_perfil":get_foto_perfil(request.user.username),
                                        "Mostrar_Contactos":True,
                                        "nav_top":nav_bar_top(u),
                                        "grupos":get_grupos_usuario(u)
                                    })      
                        else:
                            return render(request,"configuracion_usuario.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "Alerta":"El username es obligatorio",
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Mostrar_Contactos":True,
                                "nav_top":nav_bar_top(u),
                                "grupos":get_grupos_usuario(u)
                            })                                
                            
                        if(u.Nombres!=Nuevo_Nombre):
                            u.Nombres=Nuevo_Nombre
                        if(u.Apellidos!=Nuevo_Apellido):
                            u.Apellidos=Nuevo_Apellido
                        if(u.Telefono!=Nuevo_Telefono):
                            u.Telefono=Nuevo_Telefono
                        if(u.Pais!=Nuevo_Pais):
                            u.Pais=Nuevo_Pais
                        if(u.Ciudad!=Nuevo_Ciudad):
                            u.Ciudad=Nuevo_Ciudad
                        if(u.Info!=Nueva_Info):
                            u.Info=Nueva_Info
                        if(Nueva_Fecha_Nacimiento and u.Fecha_Nacimiento!=Nueva_Fecha_Nacimiento):
                            fecha = datetime.strptime(Nueva_Fecha_Nacimiento, '%Y-%m-%d')
                            u.Fecha_Nacimiento=fecha
                        if(u.username!=Nuevo_username):
                            u.username=Nuevo_username
                            request.user.username=Nuevo_username
                            request.user.save()
                        u.save()
                        return render(request,"configuracion_usuario.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Mostrar_Contactos":True,
                            "nav_top":nav_bar_top(u),
                            "grupos":get_grupos_usuario(u),
                            "Alerta":"Informacion actualizada correctamente"
                        })
                    except Exception as e:
                        return render(request,"configuracion_usuario.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "Alerta":str(e),
                            "nav_top":nav_bar_top(u),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Mostrar_Contactos":True,
                            "grupos":get_grupos_usuario(u)
                        })                                            
                elif(opc=="config-cambiar-clave"):
                    actual=request.POST.get("password-actual")                    
                    password1=request.POST.get("password1")
                    password2=request.POST.get("password2")
                    if(actual=="" or password1=="" or password2==""):
                        return render(request,"configuracion_usuario.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "Alerta":"Todos los campos son obligatorios",
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Mostrar_Contactos":True,
                            "grupos":get_grupos_usuario(u),
                            "nav_top":nav_bar_top(u),
                        })                                                   

                    if(request.user.check_password(actual)):
                        if(password1==password2):
                            # Verificar longitud mínima de 8 caracteres
                            if len(password1) < 8:
                                return render(request,"configuracion_usuario.html",{
                                    "usuario":u,"contactos":getContactos(u.username),
                                    "Alerta":"Contraseña muy corta",
                                    "url_foto_perfil":get_foto_perfil(request.user.username),
                                    "Mostrar_Contactos":True,
                                    "nav_top":nav_bar_top(u),
                                    "grupos":get_grupos_usuario(u)
                                })                           
                            
                            # Verificar si contiene al menos un número
                            if not any(char.isdigit() for char in password1):
                                return render(request,"configuracion_usuario.html",{
                                    "usuario":u,"contactos":getContactos(u.username),
                                    "Alerta":"La contraseña debe contener numeros",
                                    "nav_top":nav_bar_top(u),
                                    "url_foto_perfil":get_foto_perfil(request.user.username),
                                    "Mostrar_Contactos":True,
                                    "grupos":get_grupos_usuario(u)
                                })                           
                            
                            # Verificar si contiene al menos una letra minúscula y una mayúscula
                            if not any(char.islower() for char in password1) or not any(char.isupper() for char in password1):
                                return render(request,"configuracion_usuario.html",{
                                    "usuario":u,"contactos":getContactos(u.username),
                                    "Alerta":'Las contraseñas debe tener mayúsculas y minúsculas',
                                    "url_foto_perfil":get_foto_perfil(request.user.username),
                                    "Mostrar_Contactos":True,
                                    "grupos":get_grupos_usuario(u),
                                    "nav_top":nav_bar_top(u),
                                })                           
                            
                            
                            # Verificar si contiene al menos un caracter especial
                            caracteres_especiales = set("[!@#$%^&*()_+-=[]{}\|;:,.<>\?]")
                            if(any(caracter in caracteres_especiales for caracter in password1)==False):
                                return render(request,"configuracion_usuario.html",{
                                    "usuario":u,"contactos":getContactos(u.username),
                                    "Alerta":'La contraseña debe tener caracteres especiales',
                                    "url_foto_perfil":get_foto_perfil(request.user.username),
                                    "Mostrar_Contactos":True,
                                    "grupos":get_grupos_usuario(u),
                                    "nav_top":nav_bar_top(u),
                                })                           
                            
                            usuario=User.objects.get(username=request.user)
                            usuario.set_password(password1)
                            usuario.save()
                            return render(request,"configuracion_usuario.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "Alerta":'Contraseña actualizada correctamente',
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Mostrar_Contactos":True,
                                "nav_top":nav_bar_top(u),
                                "grupos":get_grupos_usuario(u)
                            })
                        else:
                            return render(request,"configuracion_usuario.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "Alerta":"Las contraseñas deben ser iguales",
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Mostrar_Contactos":True,
                                "grupos":get_grupos_usuario(u),
                                "nav_top":nav_bar_top(u),
                            })                               
                            
                    else:
                        return render(request,"configuracion_usuario.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "Alerta":"Contraseña incorrecta",
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Mostrar_Contactos":True,
                            "grupos":get_grupos_usuario(u),
                            "nav_top":nav_bar_top(u),
                        })                           
                elif(opc=="config-eliminar-cuenta"):
                    u.delete()
                    request.user.delete()
                    return redirect("index")
                elif(opc=='config-cambiar-foto-perfil'):
                    if('imagen' in request.FILES):
                        if(len(request.FILES)==1):
                            imagen = request.FILES.get('imagen')
                            if not validar_imagen(imagen):
                                return render(request,"configuracion_usuario.html",{
                                    "usuario":u,"contactos":getContactos(u.username),
                                    "Alerta":"Error, El archivo subido no es una Imagen valida",
                                    "url_foto_perfil":get_foto_perfil(request.user.username),
                                    "Mostrar_Contactos":True,
                                    "grupos":get_grupos_usuario(u),
                                    "nav_top":nav_bar_top(u),
                                })    
                            u.Foto_Perfil.save(imagen.name,imagen)
                            u.url_foto_perfil=get_foto_perfil(u.username)
                            u.save()
                            return render(request,"configuracion_usuario.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Mostrar_Contactos":True,
                                "grupos":get_grupos_usuario(u),
                                "nav_top":nav_bar_top(u),
                            })
                        else:
                            return render(request,"configuracion_usuario.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "Alerta":"Error, suba una sola imagen",
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Mostrar_Contactos":True,
                                "grupos":get_grupos_usuario(u),
                                "nav_top":nav_bar_top(u),
                            })
                    else:
                        return render(request,"configuracion_usuario.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "Alerta":"Error, No ha subido ninguna imagen",
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Mostrar_Contactos":True,
                            "grupos":get_grupos_usuario(u),
                            "nav_top":nav_bar_top(u),
                        })
                elif(opc=='post-new-publicacion'):
                    if('imagen' in request.FILES):
                        if(len(request.FILES)==1):
                            imagen = request.FILES.get('imagen')
                            texto = request.POST.get("descripcion")
                            if(not validar_imagen(imagen)):
                                return render(request,"perfil_propio.html",{
                                    "usuario":u,"contactos":getContactos(u.username),
                                    "url_foto_perfil":get_foto_perfil(request.user.username),
                                    "Alerta":"Error, Solo puede subir imagenes",
                                    "publicaciones":get_publicaciones_personales(u,u),
                                    "Mostrar_Contactos":True,
                                    "grupos":get_grupos_usuario(u),
                                    "nav_top":nav_bar_top(u),
                                })        
                            
                            fin=False
                            token=""
                            while(not fin):
                                token=uuid.uuid4()
                                if(list(Publicacion_Personal.objects.filter(token=token)).__len__()==0):
                                    fin=True
                            
                            nueva_publicacion = Publicacion_Personal(UsuarioID=u,texto=texto,token=token)
                            nueva_publicacion.save()
                            nueva_publicacion.imagen.save(imagen.name,imagen)
                            nueva_publicacion.url_imagen=get_foto_publicacion_personal(nueva_publicacion)
                            nueva_publicacion.save()
                            return render(request,"perfil_propio.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Alerta":"Publicacion Realizada con exito",
                                "publicaciones":get_publicaciones_personales(u,u),
                                "Mostrar_Contactos":True,
                                "grupos":get_grupos_usuario(u),
                                "nav_top":nav_bar_top(u),
                            })                             
                        else:
                            return render(request,"perfil_propio.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Alerta":"Error, Solo puede postear una Imagen",
                                "publicaciones":get_publicaciones_personales(u,u),
                                "Mostrar_Contactos":True,
                                "grupos":get_grupos_usuario(u),
                                "nav_top":nav_bar_top(u),
                            })                             
                    else:
                        return render(request,"perfil_propio.html",
                        {
                                "usuario":u,
                                "contactos":getContactos(u.username),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Alerta":"Error, debe postear una imagen",
                                "publicaciones":get_publicaciones_personales(u,u),
                                "Mostrar_Contactos":True,
                                "grupos":get_grupos_usuario(u),
                                "nav_top":nav_bar_top(u),
                        })
                elif(opc=="eliminar-publicacion-personal"):
                    id_user=request.user.id
                    token=request.POST.get("token")
                    publicacion=list(Publicacion_Personal.objects.filter(token=token))
                    if(publicacion.__len__()==0):
                        return render(request,"perfil_propio.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Alerta":"Error al eliminar publicacion",
                            "publicaciones":get_publicaciones_personales(u,u),
                            "Mostrar_Contactos":True,
                            "grupos":get_grupos_usuario(u),
                            "nav_top":nav_bar_top(u),
                        })                             
                    else:
                        publicacion=publicacion[0]
                        if(publicacion.UsuarioID.username==u.username):                            
                            publicacion.delete()
                            return render(request,"perfil_propio.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "url_foto_perfil":get_foto_perfil(request.user.username)
                                ,"Alerta":"Publicaicon eliminada con exito",
                                "publicaciones":get_publicaciones_personales(u,u),
                                "Mostrar_Contactos":True,
                                "grupos":get_grupos_usuario(u),
                                "nav_top":nav_bar_top(u),
                            })                             
                        else:
                            return render(request,"perfil_propio.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Alerta":"Error, Usted no es propietario de esta publicacion",
                                "publicaciones":get_publicaciones_personales(u,u),
                                "Mostrar_Contactos":True,
                                "grupos":get_grupos_usuario(u),
                                "nav_top":nav_bar_top(u),
                            })                             
                elif(opc=="buscar"):
                    busqueda=request.POST.get("input-busqueda")
                    if(not busqueda):
                        return render(request,"home.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Alerta":"No envió ningun valor en la busqueda",
                            "Mostrar_Contactos":True,
                            "grupos":get_grupos_usuario(u),
                            "nav_top":nav_bar_top(u),
                        })
                    else:
                        return render(request,"resultado_busqueda.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "resultado_usuarios":busqueda_contacto(busqueda),
                            "resultado_grupos":busqueda_grupo(busqueda,u),
                            "elemento_busqueda":busqueda,
                            "Mostrar_Contactos":True,
                            "grupos":get_grupos_usuario(u),
                            "nav_top":nav_bar_top(u),
                        })
                elif(opc=="agregar-contacto"):
                    quien=request.POST.get("quien")
                    quien=list(Usuario.objects.filter(username=quien))
                    if(quien.__len__()>0):
                        try:
                            nuevo_contacto=Contacto(Usuario_ID=u,ContactoUser_ID=quien[0])
                            nuevo_contacto.save()
                            return render(request,"perfil_usuario.html",{
                                "usuario":u,
                                "contactos":getContactos(u.username),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "quien":quien[0],
                                "publicaciones":get_publicaciones_personales(quien[0].username,u),
                                "Mostrar_Contactos":True,
                                "grupos":get_grupos_usuario(u),
                                "nav_top":nav_bar_top(u),
                            })
                        except Exception as e:
                            return render(request,"perfil_usuario.html",{
                                "usuario":u,
                                "contactos":getContactos(u.username),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "quien":quien[0],
                                "publicaciones":get_publicaciones_personales(quien[0].username,u),
                                "Mostrar_Contactos":True,
                                "grupos":get_grupos_usuario(u),
                                "nav_top":nav_bar_top(u),
                            })
                    else:
                        return render(request,"home.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Alerta":"El usuario ya no existe",
                            "Mostrar_Contactos":True,
                            "grupos":get_grupos_usuario(u),
                            "nav_top":nav_bar_top(u),
                        })
                elif(opc=="eliminar-contacto"):
                    quien=request.POST.get("quien")
                    cont_user=list(Usuario.objects.filter(username=quien))
                    if(cont_user.__len__()>0):
                        contacto_eliminar=list(Contacto.objects.filter(Usuario_ID=u,ContactoUser_ID=cont_user[0]))
                        if(contacto_eliminar.__len__()>0):                        
                            contacto_eliminar[0].delete()
                            return render(request,"perfil_usuario.html",{
                                "usuario":u,
                                "contactos":getContactos(u.username),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "quien":cont_user[0],
                                "publicaciones":get_publicaciones_personales(quien,u),
                                "Mostrar_Contactos":True,
                                "nav_top":nav_bar_top(u),
                            })
                        else:
                            return render(request,"perfil_usuario.html",{
                                "usuario":u,
                                "contactos":getContactos(u.username),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "quien":cont_user[0],
                                "publicaciones":get_publicaciones_personales(quien,u),
                                "Alerta":"Acceso Denegado",
                                "Mostrar_Contactos":True,
                                "nav_top":nav_bar_top(u),
                            })
                    else:
                        return render(request,"home.html",{
                            "usuario":u,
                            "contactos":getContactos(u.username),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Alerta":"Acceso Denegado",
                            "Mostrar_Contactos":True,
                            "nav_top":nav_bar_top(u),
                        })    
                elif(opc=="nuevo-grupo"):
                    Nombre_Grupo=request.POST.get("nombre_grupo")
                    Info=request.POST.get("input-info")
                    if("" in [Nombre_Grupo,Info]):
                        return render(request,"home.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Mostrar_Grupos":True,
                            "Alerta":"Aun hay Campos obligatorios",
                            "Nombre_Grupo":Nombre_Grupo,"Info":Info,
                            "grupos":get_grupos_usuario(u),
                            "nav_top":nav_bar_top(u),
                        })        
                    if('imagen' in request.FILES):
                        if(len(request.FILES)==1):
                            imagen = request.FILES.get('imagen')
                            if not validar_imagen(imagen):
                                return render(request,"home.html",{
                                    "usuario":u,"contactos":getContactos(u.username),
                                    "url_foto_perfil":get_foto_perfil(request.user.username),
                                    "Mostrar_Grupos":True,
                                    "Alerta":"Error, El archivo subido no es una Imagen valida",
                                    "Nombre_Grupo":Nombre_Grupo,"Info":Info,
                                    "grupos":get_grupos_usuario(u),
                                    "nav_top":nav_bar_top(u),
                                })
                            try:
                                nuevo_grupo=Grupo(Nombre_Grupo=Nombre_Grupo,Info=Info)
                                nuevo_grupo.imagen.save(imagen.name,imagen)
                                nuevo_grupo.url_imagen=get_foto_grupo(nuevo_grupo)
                                nuevo_grupo.save()
                                admin=Grupo_Member(Grupo_ID=nuevo_grupo,Usuario_ID=u,Admin=True)
                                admin.save()
                                return render(request,"home.html",{
                                    "usuario":u,"contactos":getContactos(u.username),
                                    "url_foto_perfil":get_foto_perfil(request.user.username),
                                    "Mostrar_Grupos":True,
                                    "Alerta":"Grupo creado Correctamente",
                                    "grupos":get_grupos_usuario(u),
                                    "nav_top":nav_bar_top(u),
                                })
                            except Exception as e:
                                return render(request,"home.html",{
                                    "usuario":u,"contactos":getContactos(u.username),
                                    "url_foto_perfil":get_foto_perfil(request.user.username),
                                    "Mostrar_Grupos":True,
                                    "Alerta":"El nombre del grupo ya esta en uso",
                                    "Nombre_Grupo":Nombre_Grupo,"Info":Info,
                                    "grupos":get_grupos_usuario(u),
                                    "nav_top":nav_bar_top(u),
                                })
                        else:
                            return render(request,"home.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Mostrar_Grupos":True,
                                "Alerta":"Error, suba una sola imagen",
                                "Nombre_Grupo":Nombre_Grupo,"Info":Info,
                                "grupos":get_grupos_usuario(u),
                                "nav_top":nav_bar_top(u),
                            })
                    try:
                        nuevo_grupo=Grupo(Nombre_Grupo=Nombre_Grupo,Info=Info)
                        nuevo_grupo.save()    
                        admin=Grupo_Member(Grupo_ID=nuevo_grupo,Usuario_ID=u,Admin=True)
                        admin.save()
                        return render(request,"home.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Mostrar_Grupos":True,
                            "Alerta":"Grupo creado Correctamente",
                            "grupos":get_grupos_usuario(u),
                            "nav_top":nav_bar_top(u),
                        })
                    except Exception as e:
                        return render(request,"home.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Mostrar_Grupos":True,
                            "grupos":get_grupos_usuario(u),
                            "Alerta":"El nombre del grupo ya esta en uso",
                            "Nombre_Grupo":Nombre_Grupo,"Info":Info,
                            "nav_top":nav_bar_top(u),
                        })
                elif(opc=="solicitud-grupo-id"):
                    grupo_id=request.POST.get("listagrupos-id-post")
                    Contexto=get_publicaciones_grupales(grupo_id,u)
                    if(Contexto is not None):
                        return render(request,"grupos/grupo.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Mostrar_Grupos":True,
                            "grupos":get_grupos_usuario(u),
                            "contexto":Contexto,
                            "nav_top":nav_bar_top(u),
                        })
                    else:
                        return render(request,"home.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Mostrar_Grupos":True,
                            "Alerta":"Acceso Denegado",
                            "grupos":get_grupos_usuario(u),
                            "nav_top":nav_bar_top(u),
                        })        
                elif(opc=="post-new-publicacion-grupal"):
                    grupo_id=request.POST.get("grupo_id")
                    Contexto=get_publicaciones_grupales(grupo_id,u)
                    grupo=list(Grupo.objects.filter(id=grupo_id))
                    if(grupo.__len__()>0):
                        grupo=grupo[0]
                        membresia=list(Grupo_Member.objects.filter(Grupo_ID=grupo,Usuario_ID=u))
                        if(membresia.__len__()>0):
                            membresia=membresia[0]
                            if('imagen' in request.FILES):
                                if(len(request.FILES)==1):
                                    imagen = request.FILES.get('imagen')
                                    texto = request.POST.get("descripcion")
                                    if(not validar_imagen(imagen)):
                                        return render(request,"grupos/grupo.html",{
                                            "usuario":u,"contactos":getContactos(u.username),
                                            "url_foto_perfil":get_foto_perfil(request.user.username),
                                            "Mostrar_Grupos":True,
                                            "grupos":get_grupos_usuario(u),
                                            "contexto":Contexto,
                                            "Alerta":"Error, Solo puede subir imagenes",
                                            "nav_top":nav_bar_top(u),
                                        })        
                                    
                                    fin=False
                                    token=""
                                    while(not fin):
                                        token=uuid.uuid4()
                                        if(list(Publicacion_Grupal.objects.filter(token=token)).__len__()==0):
                                            fin=True
                                    
                                    nueva_publicacion = Publicacion_Grupal(Grupo_ID=grupo,Grupo_Member_ID=membresia,texto=texto,token=token)
                                    nueva_publicacion.save()
                                    nueva_publicacion.imagen.save(imagen.name,imagen)
                                    nueva_publicacion.url_imagen=get_foto_publicacion_personal(nueva_publicacion)
                                    nueva_publicacion.save()
                                    Contexto=get_publicaciones_grupales(grupo_id,u)
                                    return render(request,"grupos/grupo.html",{
                                        "usuario":u,"contactos":getContactos(u.username),
                                        "url_foto_perfil":get_foto_perfil(request.user.username),
                                        "Mostrar_Grupos":True,
                                        "grupos":get_grupos_usuario(u),
                                        "contexto":Contexto,
                                        "Alerta":"Publicacion realizada con exito",
                                        "nav_top":nav_bar_top(u),
                                    })        
                                else:
                                    return render(request,"grupos/grupo.html",{
                                        "usuario":u,"contactos":getContactos(u.username),
                                        "url_foto_perfil":get_foto_perfil(request.user.username),
                                        "Mostrar_Grupos":True,
                                        "grupos":get_grupos_usuario(u),
                                        "contexto":Contexto,
                                        "Alerta":"Error, Solo puede postear una Imagen",
                                        "nav_top":nav_bar_top(u),
                                    })        
                            else:
                                return render(request,"grupos/grupo.html",{
                                    "usuario":u,"contactos":getContactos(u.username),
                                    "url_foto_perfil":get_foto_perfil(request.user.username),
                                    "Mostrar_Grupos":True,
                                    "grupos":get_grupos_usuario(u),
                                    "contexto":Contexto,
                                    "Alerta":"Error, debe postear una imagen",
                                    "nav_top":nav_bar_top(u),
                                })        
                elif(opc=="eliminar-publicacion-grupal"):
                    id_user=request.user.id
                    token=request.POST.get("token")
                    publicacion=list(Publicacion_Grupal.objects.filter(token=token))
                    
                    if(publicacion.__len__()==0):
                        return render(request,"home.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Mostrar_Grupos":True,
                            "Alerta":"Error al eliminar publicacion",
                            "grupos":get_grupos_usuario(u),
                            "nav_top":nav_bar_top(u),
                        })
                    else:
                        publicacion=publicacion[0]
                        grupo_id=publicacion.Grupo_Member_ID.Grupo_ID.id
                        Contexto=get_publicaciones_grupales(grupo_id,u)
                        if(publicacion.Grupo_Member_ID.Usuario_ID==u or Contexto["Admin"]==True):
                            publicacion.delete()
                            Contexto=get_publicaciones_grupales(grupo_id,u)
                            return render(request,"grupos/grupo.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Mostrar_Grupos":True,
                                "grupos":get_grupos_usuario(u),
                                "contexto":Contexto,
                                "Alerta":"Publicacion eliminada con exito",
                                "nav_top":nav_bar_top(u),
                            })                
                        else:
                            return render(request,"grupos/grupo.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Mostrar_Grupos":True,
                                "grupos":get_grupos_usuario(u),
                                "contexto":Contexto,
                                "Alerta":"Error, Usted no es propietario de esta publicacion",
                                "nav_top":nav_bar_top(u),
                                "nav_top":nav_bar_top(u),
                            })
                elif(opc=="config-cambiar-foto-perfil-grupo"):
                    grupo_id=request.POST.get("grupo_id")
                    grupo=list(Grupo.objects.filter(id=grupo_id))
                    if(grupo.__len__()>0):
                        grupo=grupo[0]
                        Contexto=get_publicaciones_grupales(grupo_id,u)
                        membresia=list(Grupo_Member.objects.filter(Grupo_ID=grupo,Usuario_ID=u))
                        if(membresia.__len__()>0 and membresia[0].Admin):
                            if('imagen' in request.FILES):
                                if(len(request.FILES)==1):
                                    imagen = request.FILES.get('imagen')
                                    if not validar_imagen(imagen):
                                        return render(request,"grupos/grupo.html",{
                                            "usuario":u,"contactos":getContactos(u.username),
                                            "url_foto_perfil":get_foto_perfil(request.user.username),
                                            "Mostrar_Grupos":True,
                                            "grupos":get_grupos_usuario(u),
                                            "contexto":Contexto,
                                            "Alerta":"Error, El archivo subido no es una Imagen valida",
                                            "nav_top":nav_bar_top(u),
                                        })                
                                    grupo.imagen.save(imagen.name,imagen)
                                    grupo.url_imagen=get_foto_grupo(grupo)
                                    grupo.save()
                                    Contexto=get_publicaciones_grupales(grupo_id,u)
                                    return render(request,"grupos/grupo.html",{
                                        "usuario":u,"contactos":getContactos(u.username),
                                        "url_foto_perfil":get_foto_perfil(request.user.username),
                                        "Mostrar_Grupos":True,
                                        "grupos":get_grupos_usuario(u),
                                        "contexto":Contexto,
                                        "Alerta":"Foto de perfil del grupo actualizada correctamente",
                                        "nav_top":nav_bar_top(u),
                                    })                
                                else:
                                    return render(request,"grupos/grupo.html",{
                                        "usuario":u,"contactos":getContactos(u.username),
                                        "url_foto_perfil":get_foto_perfil(request.user.username),
                                        "Mostrar_Grupos":True,
                                        "grupos":get_grupos_usuario(u),
                                        "contexto":Contexto,
                                        "Alerta":"Error, suba una sola imagen",
                                        "nav_top":nav_bar_top(u),
                                    })                
                            else:
                                return render(request,"grupos/grupo.html",{
                                    "usuario":u,"contactos":getContactos(u.username),
                                    "url_foto_perfil":get_foto_perfil(request.user.username),
                                    "Mostrar_Grupos":True,
                                    "grupos":get_grupos_usuario(u),
                                    "contexto":Contexto,
                                    "Alerta":"Error, No ha subido ninguna imagen",
                                    "nav_top":nav_bar_top(u),
                                })                
                        else:
                            return render(request,"grupos/grupo.html",{
                                    "usuario":u,"contactos":getContactos(u.username),
                                    "url_foto_perfil":get_foto_perfil(request.user.username),
                                    "Mostrar_Grupos":True,
                                    "grupos":get_grupos_usuario(u),
                                    "contexto":Contexto,
                                    "Alerta":"Error, Acceso Denegado",
                                    "nav_top":nav_bar_top(u),
                                })                
                    else:
                        return render(request,"home.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "grupos":get_grupos_usuario(u),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Mostrar_Grupos":True,
                            "Alerta":"Error",
                            "nav_top":nav_bar_top(u),
                        })
                elif(opc=="config-eliminar-grupo"):
                    grupo_id=request.POST.get("grupo_id")
                    grupo=list(Grupo.objects.filter(id=grupo_id))
                    if(grupo.__len__()>0):
                        grupo=grupo[0]
                        Contexto=get_publicaciones_grupales(grupo_id,u)
                        membresia=list(Grupo_Member.objects.filter(Grupo_ID=grupo,Usuario_ID=u))
                        if(membresia.__len__()>0 and membresia[0].Admin):
                            grupo.delete()
                            return render(request,"home.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "grupos":get_grupos_usuario(u),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Mostrar_Grupos":True,
                                "Alerta":"Grupo Eliminado correctamente",
                                "nav_top":nav_bar_top(u),
                            })    
                        else:
                            return render(request,"grupos/grupo.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Mostrar_Grupos":True,
                                "grupos":get_grupos_usuario(u),
                                "contexto":Contexto,
                                "Alerta":"Error, Acceso Denegado",
                                "nav_top":nav_bar_top(u),
                            })                
                    else:
                        return render(request,"home.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "grupos":get_grupos_usuario(u),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Mostrar_Grupos":True,
                            "Alerta":"Error","nav_top":nav_bar_top(u),
                        })
                elif(opc=="config-grupo-cambiar-info"):
                    grupo_id=request.POST.get("grupo_id")
                    grupo=list(Grupo.objects.filter(id=grupo_id))
                    if(grupo.__len__()>0):
                        grupo=grupo[0]
                        Contexto=get_publicaciones_grupales(grupo_id,u)
                        membresia=list(Grupo_Member.objects.filter(Grupo_ID=grupo,Usuario_ID=u))
                        if(membresia.__len__()>0 and membresia[0].Admin):
                            Nombre_Grupo=request.POST.get("input_nombre_grupo")
                            Info=request.POST.get("input_info")
                            if("" in [Nombre_Grupo,Info]):
                                return render(request,"grupos/grupo.html",{
                                    "usuario":u,"contactos":getContactos(u.username),
                                    "url_foto_perfil":get_foto_perfil(request.user.username),
                                    "Mostrar_Grupos":True,
                                    "grupos":get_grupos_usuario(u),
                                    "contexto":Contexto,
                                    "Alerta":"Error, todos los campos obligatorios",
                                    "nav_top":nav_bar_top(u),
                                })                
                            grupo.Nombre_Grupo=Nombre_Grupo
                            grupo.Info=Info
                            grupo.save()
                            Contexto=get_publicaciones_grupales(grupo_id,u)
                            return render(request,"grupos/grupo.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Mostrar_Grupos":True,
                                "grupos":get_grupos_usuario(u),
                                "contexto":Contexto,
                                "nav_top":nav_bar_top(u),
                            })                
                        else:
                            return render(request,"grupos/grupo.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Mostrar_Grupos":True,
                                "grupos":get_grupos_usuario(u),
                                "contexto":Contexto,
                                "Alerta":"Error, Acceso Denegado",
                                "nav_top":nav_bar_top(u),
                            })                
                    else:
                        return render(request,"home.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "grupos":get_grupos_usuario(u),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Mostrar_Grupos":True,
                            "Alerta":"Error",
                            "nav_top":nav_bar_top(u),
                        })
                elif(opc=="solicitud-grupo"):
                    grupo_id=request.POST.get("grupo_id")
                    Contexto=get_publicaciones_grupales(grupo_id,u)
                    if(Contexto is not None):
                        try:
                            solicitud=Solicitud(Grupo_ID=Contexto["grupo"],Usuario_ID=u)
                            solicitud.save()
                            Contexto=get_publicaciones_grupales(grupo_id,u)
                            return render(request,"grupos/grupo.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Mostrar_Grupos":True,
                                "grupos":get_grupos_usuario(u),
                                "contexto":Contexto,
                                "nav_top":nav_bar_top(u),
                            })
                        except Exception as e:
                            return render(request,"grupos/grupo.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Mostrar_Grupos":True,
                                "grupos":get_grupos_usuario(u),
                                "contexto":Contexto,
                                "nav_top":nav_bar_top(u),
                            })
                    else:
                        return render(request,"home.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Mostrar_Grupos":True,
                            "Alerta":"Acceso Denegado",
                            "grupos":get_grupos_usuario(u),
                            "nav_top":nav_bar_top(u),
                        })       
                elif(opc=="eliminar-solicitud-grupo"):
                    grupo_id=request.POST.get("grupo_id")
                    Contexto=get_publicaciones_grupales(grupo_id,u)
                    if(Contexto is not None):
                        try:
                            solicitud=list(Solicitud.objects.filter(Usuario_ID=u,Grupo_ID=Contexto["grupo"]))
                            if(solicitud.__len__()>0):
                                solicitud[0].delete()
                                Contexto=get_publicaciones_grupales(grupo_id,u)
                                return render(request,"grupos/grupo.html",{
                                    "usuario":u,"contactos":getContactos(u.username),
                                    "url_foto_perfil":get_foto_perfil(request.user.username),
                                    "Mostrar_Grupos":True,
                                    "grupos":get_grupos_usuario(u),
                                    "contexto":Contexto,
                                    "nav_top":nav_bar_top(u),
                                })
                            else:
                                return render(request,"grupos/grupo.html",{
                                    "usuario":u,"contactos":getContactos(u.username),
                                    "url_foto_perfil":get_foto_perfil(request.user.username),
                                    "Mostrar_Grupos":True,
                                    "grupos":get_grupos_usuario(u),
                                    "contexto":Contexto,
                                    "nav_top":nav_bar_top(u),
                                })
                        except Exception as e:
                            return render(request,"grupos/grupo.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Mostrar_Grupos":True,
                                "grupos":get_grupos_usuario(u),
                                "contexto":Contexto,
                                "nav_top":nav_bar_top(u),
                            })
                    else:
                        return render(request,"home.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Mostrar_Grupos":True,
                            "Alerta":"Acceso Denegado",
                            "grupos":get_grupos_usuario(u),
                            "nav_top":nav_bar_top(u),
                        })       
                elif(opc=="get-atender-solicitudes"):
                    grupo_id=request.POST.get("grupo_id")
                    Contexto=get_publicaciones_grupales(grupo_id,u)
                    if(Contexto is not None):
                        if(Contexto["Admin"]==True):
                            solicitudes=get_solicitudes_grupo(grupo=Contexto["grupo"])
                            return render(request,"grupos/solicitudes.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "grupos":get_grupos_usuario(u),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Mostrar_Grupos":True,
                                "contexto":Contexto,
                                "solicitudes":solicitudes,
                                "nav_top":nav_bar_top(u),
                            })
                        else:
                            return render(request,"grupos/grupo.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Mostrar_Grupos":True,
                                "grupos":get_grupos_usuario(u),
                                "contexto":Contexto,
                                "Alerta":"Error, Usted no es Administrador",
                                "nav_top":nav_bar_top(u),
                            })
                    else:
                        return render(request,"home.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Mostrar_Contactos":True,
                            "grupos":get_grupos_usuario(u),
                            "Alerta":"Acceso Denegado",
                            "nav_top":nav_bar_top(u),
                        })        
                elif(opc=="aceptar_solicitud"):
                    grupo_id=request.POST.get("grupo_id")
                    Contexto=get_publicaciones_grupales(grupo_id,u)
                    if(Contexto is not None):
                        if(Contexto["Admin"]==True):
                            nuevo=list(Usuario.objects.filter(username=request.POST.get("username")))
                            if(nuevo.__len__()>0):
                                nuevo=nuevo[0]
                                solicitud=list(Solicitud.objects.filter(Usuario_ID=nuevo,Grupo_ID=Contexto["grupo"]))
                                if(solicitud.__len__()>0):
                                    solicitud[0].delete()
                                    existe=list(Grupo_Member.objects.filter(Grupo_ID=Contexto["grupo"],Usuario_ID=nuevo))
                                    if(existe.__len__()>0):
                                        return render(request,"grupos/solicitudes.html",{
                                            "usuario":u,"contactos":getContactos(u.username),
                                            "grupos":get_grupos_usuario(u),
                                            "url_foto_perfil":get_foto_perfil(request.user.username),
                                            "Mostrar_Grupos":True,
                                            "contexto":Contexto,
                                            "solicitudes":get_solicitudes_grupo(Contexto["grupo"]),
                                            "Alerta":"Error, Este usuario ya es miembro",
                                            "nav_top":nav_bar_top(u),
                                        })        
                                    else:
                                        nuevo_miembro=Grupo_Member(Grupo_ID=Contexto["grupo"],Usuario_ID=nuevo,Admin=False)
                                        nuevo_miembro.save()
                                        return render(request,"grupos/solicitudes.html",{
                                            "usuario":u,"contactos":getContactos(u.username),
                                            "grupos":get_grupos_usuario(u),
                                            "url_foto_perfil":get_foto_perfil(request.user.username),
                                            "Mostrar_Grupos":True,
                                            "contexto":Contexto,
                                            "solicitudes":get_solicitudes_grupo(Contexto["grupo"]),
                                            "nav_top":nav_bar_top(u),
                                        })
                                else:
                                    return render(request,"grupos/solicitudes.html",{
                                        "usuario":u,"contactos":getContactos(u.username),
                                        "grupos":get_grupos_usuario(u),
                                        "url_foto_perfil":get_foto_perfil(request.user.username),
                                        "Mostrar_Grupos":True,
                                        "contexto":Contexto,
                                        "solicitudes":get_solicitudes_grupo(Contexto["grupo"]),
                                        "Alerta":"Error, Solicitud no registrada",
                                        "nav_top":nav_bar_top(u),
                                    })    

                            else:
                                return render(request,"grupos/solicitudes.html",{
                                    "usuario":u,"contactos":getContactos(u.username),
                                    "grupos":get_grupos_usuario(u),
                                    "url_foto_perfil":get_foto_perfil(request.user.username),
                                    "Mostrar_Grupos":True,
                                    "contexto":Contexto,
                                    "solicitudes":get_solicitudes_grupo(Contexto["grupo"]),
                                    "Alerta":"Error, Usuario no encontrado",
                                    "nav_top":nav_bar_top(u),
                                })    
                        else:
                            return render(request,"grupos/solicitudes.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "grupos":get_grupos_usuario(u),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Mostrar_Grupos":True,
                                "contexto":Contexto,
                                "solicitudes":get_solicitudes_grupo(Contexto["grupo"]),
                                "nav_top":nav_bar_top(u),
                            })    
                    else:
                        return render(request,"home.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Mostrar_Contactos":True,
                            "grupos":get_grupos_usuario(u),
                            "Alerta":"Acceso Denegado",
                            "nav_top":nav_bar_top(u),
                        })        
                elif(opc=="cancelar_solicitud"):
                    grupo_id=request.POST.get("grupo_id")
                    Contexto=get_publicaciones_grupales(grupo_id,u)
                    if(Contexto is not None):
                        if(Contexto["Admin"]==True):
                            nuevo=list(Usuario.objects.filter(username=request.POST.get("username")))
                            if(nuevo.__len__()>0):
                                nuevo=nuevo[0]
                                solicitud=list(Solicitud.objects.filter(Usuario_ID=nuevo,Grupo_ID=Contexto["grupo"]))
                                if(solicitud.__len__()>0):
                                    solicitud[0].delete()
                                    return render(request,"grupos/solicitudes.html",{
                                        "usuario":u,"contactos":getContactos(u.username),
                                        "grupos":get_grupos_usuario(u),
                                        "url_foto_perfil":get_foto_perfil(request.user.username),
                                        "Mostrar_Grupos":True,
                                        "contexto":get_publicaciones_grupales(grupo_id,u),
                                        "solicitudes":get_solicitudes_grupo(Contexto["grupo"]),
                                        "nav_top":nav_bar_top(u),
                                    })
                                else:
                                    return render(request,"grupos/solicitudes.html",{
                                        "usuario":u,"contactos":getContactos(u.username),
                                        "grupos":get_grupos_usuario(u),
                                        "url_foto_perfil":get_foto_perfil(request.user.username),
                                        "Mostrar_Grupos":True,
                                        "contexto":Contexto,
                                        "solicitudes":get_solicitudes_grupo(Contexto["grupo"]),
                                        "Alerta":"Error, Solicitud no registrada",
                                        "nav_top":nav_bar_top(u),
                                    })    

                            else:
                                return render(request,"grupos/solicitudes.html",{
                                    "usuario":u,"contactos":getContactos(u.username),
                                    "grupos":get_grupos_usuario(u),
                                    "url_foto_perfil":get_foto_perfil(request.user.username),
                                    "Mostrar_Grupos":True,
                                    "contexto":Contexto,
                                    "solicitudes":get_solicitudes_grupo(Contexto["grupo"]),
                                    "Alerta":"Error, Usuario no encontrado",
                                    "nav_top":nav_bar_top(u),
                                })    
                        else:
                            return render(request,"grupos/solicitudes.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "grupos":get_grupos_usuario(u),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Mostrar_Grupos":True,
                                "contexto":Contexto,
                                "solicitudes":get_solicitudes_grupo(Contexto["grupo"]),
                                "nav_top":nav_bar_top(u),
                            })    
                    else:
                        return render(request,"home.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Mostrar_Contactos":True,
                            "grupos":get_grupos_usuario(u),
                            "Alerta":"Acceso Denegado",
                            "nav_top":nav_bar_top(u),
                        })        
                elif(opc=="eliminar-membresia-propia"):
                    grupo_id=request.POST.get("grupo_id")
                    Contexto=get_publicaciones_grupales(grupo_id,u)
                    if(Contexto is not None):
                        membresia=list(Grupo_Member.objects.filter(Grupo_ID=Contexto["grupo"],Usuario_ID=u))
                        if(membresia.__len__()>0):
                            membresia[0].delete()
                            Contexto=get_publicaciones_grupales(grupo_id,u)
                            return render(request,"grupos/grupo.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Mostrar_Grupos":True,
                                "grupos":get_grupos_usuario(u),
                                "contexto":Contexto,
                                "nav_top":nav_bar_top(u),
                            })   
                        else: 
                            return render(request,"grupos/grupo.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Mostrar_Grupos":True,
                                "grupos":get_grupos_usuario(u),
                                "contexto":Contexto,
                                "nav_top":nav_bar_top(u),
                            })   
                    else:
                        return render(request,"home.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Mostrar_Contactos":True,
                            "grupos":get_grupos_usuario(u),
                            "Alerta":"Acceso Denegado",
                            "nav_top":nav_bar_top(u),
                        })        
                elif(opc=="eliminar_miembro"):
                    grupo_id=request.POST.get("grupo_id")
                    Contexto=get_publicaciones_grupales(grupo_id,u)
                    if(Contexto is not None):
                        if(Contexto["Admin"]==True):
                            deleter=list(Usuario.objects.filter(username=request.POST.get("username")))
                            if(deleter.__len__()>0 and deleter[0].username!=u.username):
                                membresia=list(Grupo_Member.objects.filter(Grupo_ID=Contexto["grupo"],Usuario_ID=deleter[0]))
                                if(membresia.__len__()>0):
                                    membresia[0].delete()
                                    return render(request,"grupos/miembros.html",{
                                        "usuario":u,"contactos":getContactos(u.username),
                                        "url_foto_perfil":get_foto_perfil(request.user.username),
                                        "Mostrar_Grupos":True,
                                        "grupos":get_grupos_usuario(u),
                                        "contexto":Contexto,
                                        "miembros":get_miembros_grupo(grupo_id),
                                        "nav_top":nav_bar_top(u),
                                    })    
                                else:
                                    return render(request,"grupos/miembros.html",{
                                        "usuario":u,"contactos":getContactos(u.username),
                                        "url_foto_perfil":get_foto_perfil(request.user.username),
                                        "Mostrar_Grupos":True,
                                        "grupos":get_grupos_usuario(u),
                                        "contexto":Contexto,
                                        "miembros":get_miembros_grupo(grupo_id),
                                        "Alerta":"Error",
                                        "nav_top":nav_bar_top(u),
                                    })    
                            else:
                                return render(request,"grupos/miembros.html",{
                                    "usuario":u,"contactos":getContactos(u.username),
                                    "url_foto_perfil":get_foto_perfil(request.user.username),
                                    "Mostrar_Grupos":True,
                                    "grupos":get_grupos_usuario(u),
                                    "contexto":Contexto,
                                    "miembros":get_miembros_grupo(grupo_id),
                                    "Alerta":"Error",
                                    "nav_top":nav_bar_top(u),
                                })
                        else:
                            return render(request,"grupos/miembros.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Mostrar_Grupos":True,
                                "grupos":get_grupos_usuario(u),
                                "contexto":Contexto,
                                "miembros":get_miembros_grupo(grupo_id),
                                "Alerta":"Error, usted no es administrador",
                                "nav_top":nav_bar_top(u),
                            })   
                    else:
                        return render(request,"home.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Mostrar_Contactos":True,
                            "grupos":get_grupos_usuario(u),
                            "Alerta":"Acceso Denegado",
                            "nav_top":nav_bar_top(u),
                        })        


                elif(opc=="get-miembros-grupo"):
                    grupo_id=request.POST.get("grupo_id")
                    grupo=list(Grupo.objects.filter(id=grupo_id))
                    if(grupo.__len__()>0):
                        return render(request,"grupos/miembros.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Mostrar_Grupos":True,
                            "grupos":get_grupos_usuario(u),
                            "contexto":get_publicaciones_grupales(grupo_id,u),
                            "miembros":get_miembros_grupo(grupo_id),
                            "nav_top":nav_bar_top(u),
                        })
                    else:
                        return render(request,"home.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Mostrar_Grupos":True,
                            "grupos":get_grupos_usuario(u),
                            "nav_top":nav_bar_top(u),
                        })
                elif(opc=="like_personal"):
                    token=request.POST.get("token")
                    publicacion=Publicacion_Personal.objects.filter(token=token).first()
                    if(publicacion and publicacion.UsuarioID!=u):
                        like=Like_Publicacion_Personal(Publicacion_Personal_ID=publicacion,Usuario_ID=u)
                        like.save()
                        return render(request,"perfil_usuario.html",{
                            "usuario":u,
                            "contactos":getContactos(u.username),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "quien":Usuario.objects.get(username=publicacion.UsuarioID),
                            "publicaciones":get_publicaciones_personales(publicacion.UsuarioID,u),
                            "Mostrar_Contactos":True,
                            "grupos":get_grupos_usuario(u),
                            "nav_top":nav_bar_top(u),
                        })
                    else:
                        return render(request,"home.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Mostrar_Contactos":True,
                            "grupos":get_grupos_usuario(u),
                            "nav_top":nav_bar_top(u),
                        })
                elif(opc=="dislike_personal"):
                    token=request.POST.get("token")
                    publicacion=Publicacion_Personal.objects.filter(token=token).first()
                    if(publicacion and publicacion.UsuarioID!=u):
                        like=Like_Publicacion_Personal.objects.filter(Publicacion_Personal_ID=publicacion,Usuario_ID=u).first()
                        if(like):
                            like.delete()
                        return render(request,"perfil_usuario.html",{
                            "usuario":u,
                            "contactos":getContactos(u.username),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "quien":Usuario.objects.get(username=publicacion.UsuarioID),
                            "publicaciones":get_publicaciones_personales(publicacion.UsuarioID,u),
                            "Mostrar_Contactos":True,
                            "grupos":get_grupos_usuario(u),
                            "nav_top":nav_bar_top(u),
                        })
                

                    else:
                        return render(request,"home.html",{
                            "usuario":u,"contactos":getContactos(u.username),
                            "url_foto_perfil":get_foto_perfil(request.user.username),
                            "Mostrar_Contactos":True,
                            "grupos":get_grupos_usuario(u),
                            "nav_top":nav_bar_top(u),
                        })
                elif(opc=="like_grupal"):
                    token=request.POST.get("token")
                    publicacion=Publicacion_Grupal.objects.filter(token=token).first()
                    if(publicacion):
                        grupo=publicacion.Grupo_ID
                        miembro=Grupo_Member.objects.filter(Grupo_ID=grupo,Usuario_ID=u).first()
                        if(publicacion.Grupo_Member_ID!=miembro):
                            try:
                                like=Like_Publicacion_Grupal(Publicacion_Grupal_ID=publicacion,GrupoMember_ID=miembro)
                                like.save()
                                Contexto=get_publicaciones_grupales(grupo.id,u)
                                if(Contexto is not None):
                                    return render(request,"grupos/grupo.html",{
                                        "usuario":u,"contactos":getContactos(u.username),
                                        "url_foto_perfil":get_foto_perfil(request.user.username),
                                        "Mostrar_Grupos":True,
                                        "grupos":get_grupos_usuario(u),
                                        "contexto":Contexto,
                                        "nav_top":nav_bar_top(u),
                                    })
                            except Exception as e:
                                return render(request,"grupos/grupo.html",{
                                    "usuario":u,"contactos":getContactos(u.username),
                                    "url_foto_perfil":get_foto_perfil(request.user.username),
                                    "Mostrar_Grupos":True,
                                    "grupos":get_grupos_usuario(u),
                                    "contexto":get_publicaciones_grupales(grupo.id,u),
                                    "Alerta":str(e),
                                    "nav_top":nav_bar_top(u),
                                })

                        else:
                            return render(request,"grupos/grupo.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Mostrar_Grupos":True,
                                "grupos":get_grupos_usuario(u),
                                "contexto":Contexto,
                                "nav_top":nav_bar_top(u),
                            })


                    return render(request,"home.html",{
                        "usuario":u,"contactos":getContactos(u.username),
                        "url_foto_perfil":get_foto_perfil(request.user.username),
                        "Mostrar_Contactos":True,
                        "grupos":get_grupos_usuario(u),
                        "nav_top":nav_bar_top(u),
                    })
                elif(opc=="dislike_grupal"):
                    token=request.POST.get("token")
                    publicacion=Publicacion_Grupal.objects.filter(token=token).first()
                    if(publicacion):
                        grupo=publicacion.Grupo_ID
                        miembro=Grupo_Member.objects.filter(Grupo_ID=grupo,Usuario_ID=u).first()
                        if(publicacion.Grupo_Member_ID!=miembro):
                            try:
                                like=Like_Publicacion_Grupal.objects.filter(Publicacion_Grupal_ID=publicacion,GrupoMember_ID=miembro).first()
                                if(like):
                                    like.delete()
                                Contexto=get_publicaciones_grupales(grupo.id,u)
                                if(Contexto is not None):
                                    return render(request,"grupos/grupo.html",{
                                        "usuario":u,"contactos":getContactos(u.username),
                                        "url_foto_perfil":get_foto_perfil(request.user.username),
                                        "Mostrar_Grupos":True,
                                        "grupos":get_grupos_usuario(u),
                                        "contexto":Contexto,
                                        "nav_top":nav_bar_top(u),
                                    })
                            except Exception as e:
                                return render(request,"grupos/grupo.html",{
                                    "usuario":u,"contactos":getContactos(u.username),
                                    "url_foto_perfil":get_foto_perfil(request.user.username),
                                    "Mostrar_Grupos":True,
                                    "grupos":get_grupos_usuario(u),
                                    "contexto":get_publicaciones_grupales(grupo.id,u),
                                    "Alerta":str(e),
                                    "nav_top":nav_bar_top(u),
                                })

                        else:
                            return render(request,"grupos/grupo.html",{
                                "usuario":u,"contactos":getContactos(u.username),
                                "url_foto_perfil":get_foto_perfil(request.user.username),
                                "Mostrar_Grupos":True,
                                "grupos":get_grupos_usuario(u),
                                "contexto":Contexto,
                                "nav_top":nav_bar_top(u),
                            })
                    return render(request,"home.html",{
                        "usuario":u,"contactos":getContactos(u.username),
                        "url_foto_perfil":get_foto_perfil(request.user.username),
                        "Mostrar_Contactos":True,
                        "grupos":get_grupos_usuario(u),
                        "nav_top":nav_bar_top(u),
                    })
            else:
                return render(request,"home.html",{
                    "usuario":u,"contactos":getContactos(u.username),
                    "url_foto_perfil":get_foto_perfil(request.user.username),
                    "Mostrar_Contactos":True,
                    "grupos":get_grupos_usuario(u),
                    "nav_top":nav_bar_top(u),
                })
    else:
        return redirect("login")