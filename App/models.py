from django.db import models
from django.contrib.auth.models import User
# Create your models here.


class Usuario(models.Model):
    username=models.CharField(null=False,editable=True,max_length=100,blank=False,unique=True)
    tocken2FA=models.BooleanField(null=False,editable=True,blank=False)
    strToken=models.CharField(null=True,editable=True,blank=True,max_length=50)
    online=models.BooleanField(null=False,editable=True,blank=False)
    
    #groups = models.ManyToManyField(Group, related_name='usuarios')
    #user_permissions = models.ManyToManyField(Permission, related_name='usuarios')
    #Lista de contactos es a traves de la tabla contactos
    #Lista de Grupos se obtiene a traves de la tabla de GrupoMembers
    #Lista de Chats se obtiene a traves de la tabla chats que contiene el id del usuario
        #El contenido de cada chat va a estar en la tabla de ContenidoChat
    
    Foto_Perfil=models.ImageField(null=True,editable=True)
    url_foto_perfil=models.CharField(null=True,editable=True,max_length=250)
    Nombres=models.CharField(null=True,editable=True,blank=True,max_length=100)
    Apellidos=models.CharField(null=True,editable=True,blank=True,max_length=100)
    Telefono=models.CharField(null=True,editable=True,blank=True,max_length=15)
    Pais=models.CharField(null=True,editable=True,blank=True,max_length=50)
    Ciudad=models.CharField(null=True,editable=True,blank=True,max_length=50)
    Info=models.CharField(null=True,editable=True,max_length=250,blank=True)
    Fecha_Nacimiento=models.DateField(null=True,blank=True,editable=True)

    def __str__(self):
        return self.username


class ResetPass(models.Model):
    UsuarioID = models.OneToOneField(Usuario, on_delete=models.CASCADE)
    strToken=models.CharField(null=True,editable=True,blank=True,max_length=50)    
    cant_intentos=models.IntegerField(null=False,editable=True,blank=False)





#PUBLICACIONES PERSONALES
class Publicacion_Personal(models.Model):
    UsuarioID = models.ForeignKey(Usuario, on_delete=models.CASCADE)
    token=models.CharField(null=False,editable=False,blank=False,max_length=250,unique=True)
    imagen=models.ImageField(null=True,editable=True)
    url_imagen=models.CharField(null=True,editable=True,max_length=250)
    texto=models.TextField(null=True,editable=True,blank=True)


class Comentario_Publicacion_Personal(models.Model):
    Publicacion_Personal_ID=models.ForeignKey(Publicacion_Personal, on_delete=models.CASCADE)
    Usuario_ID=models.ForeignKey(Usuario, on_delete=models.CASCADE)
    texto_comentario = models.TextField(null=True,editable=True,blank=True)

class Like_Publicacion_Personal(models.Model):
    Publicacion_Personal_ID=models.ForeignKey(Publicacion_Personal, on_delete=models.CASCADE)
    Usuario_ID=models.ForeignKey(Usuario, on_delete=models.CASCADE)
###################################################################################################
    

class Contacto(models.Model):
    Usuario_ID = models.ForeignKey(Usuario, on_delete=models.CASCADE,related_name='duenio')
    ContactoUser_ID=models.ForeignKey(Usuario, on_delete=models.CASCADE,related_name='contacto')
    class Meta:
        unique_together = ('Usuario_ID', 'ContactoUser_ID')

##################################################################################################


class Grupo(models.Model):
    Nombre_Grupo=models.CharField(unique=True,null=False,editable=True,max_length=50,blank=False)
    Info=models.CharField(null=True,editable=True,max_length=250,blank=True)
    imagen=models.ImageField(null=True,editable=True)
    url_imagen=models.CharField(null=True,editable=True,max_length=250)

class Solicitud(models.Model):
    Grupo_ID=models.ForeignKey(Grupo,on_delete=models.CASCADE)
    Usuario_ID = models.ForeignKey(Usuario, on_delete=models.CASCADE)
    class Meta:
        unique_together = ('Grupo_ID', 'Usuario_ID')

class Grupo_Member(models.Model):
    Grupo_ID = models.ForeignKey(Grupo, on_delete=models.CASCADE)
    Usuario_ID = models.ForeignKey(Usuario, on_delete=models.CASCADE)
    Admin=models.BooleanField(null=False,blank=False)



#PUBLICACIONES GRUPALES
class Publicacion_Grupal(models.Model):
    Grupo_ID=models.ForeignKey(Grupo,on_delete=models.CASCADE)
    Grupo_Member_ID=models.ForeignKey(Grupo_Member,on_delete=models.CASCADE)
    texto=models.TextField(null=True,editable=True,blank=True)
    imagen=models.ImageField(null=True,editable=True)
    url_imagen=models.CharField(null=True,editable=True,max_length=250)
    token=models.CharField(null=False,editable=False,blank=False,max_length=250,unique=True)




class Comentario_Publicacion_Grupal(models.Model):
    Publicacion_Grupal_ID=models.ForeignKey(Publicacion_Grupal, on_delete=models.CASCADE)
    Grupo_Member_ID=models.ForeignKey(Grupo_Member,on_delete=models.CASCADE)
    texto_comentario = models.TextField(null=True,editable=True,blank=True)


class Like_Publicacion_Grupal(models.Model):
    Publicacion_Grupal_ID=models.ForeignKey(Publicacion_Grupal, on_delete=models.CASCADE)
    GrupoMember_ID=models.ForeignKey(Grupo_Member,on_delete=models.CASCADE)



################################################################################################



class ContenidoGrupo(models.Model):
    Grupo_ID = models.ForeignKey(Grupo, on_delete=models.CASCADE)
    Usuario_ID = models.ForeignKey(Usuario, on_delete=models.CASCADE)
    Mensaje = models.TextField(null=False,blank=False)
    Fecha=models.DateTimeField(null=False,blank=False)




class Chat(models.Model):
    Contacto_ID = models.ForeignKey(Contacto, on_delete=models.CASCADE)



class ContenidoChat(models.Model):
    Chat_ID = models.ForeignKey(Chat, on_delete=models.CASCADE)
    Usuario_ID = models.ForeignKey(Usuario, on_delete=models.CASCADE)
    Mensaje = models.TextField(null=False,blank=False)
    Fecha=models.DateTimeField(null=False,blank=False)
