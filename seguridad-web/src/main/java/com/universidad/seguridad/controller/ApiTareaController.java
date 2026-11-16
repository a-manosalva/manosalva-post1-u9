package com.universidad.seguridad.controller;

import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.universidad.seguridad.model.Tarea;
import com.universidad.seguridad.model.Usuario;
import com.universidad.seguridad.repository.UsuarioRepository;
import com.universidad.seguridad.service.TareaService;

@RestController
@RequestMapping("/api/tareas")
public class ApiTareaController {

    private final TareaService service;
    private final UsuarioRepository usuarioRepository;

    public ApiTareaController(TareaService service, UsuarioRepository usuarioRepository) {
        this.service = service;
        this.usuarioRepository = usuarioRepository;
    }

    @GetMapping
    public List<Tarea> misTareas(Authentication auth) {
        // Authentication llega poblado por JwtAuthFilter, exactamente
        // como llegaría si la petición viniera autenticada por sesión:
        // el resto de la aplicación no necesita saber cuál mecanismo
        // se usó para autenticar a este usuario.
        Usuario usuario = usuarioRepository.findByEmail(auth.getName())
            .orElseThrow(() -> new ResponseStatusException(
                HttpStatus.UNAUTHORIZED, "Usuario autenticado no encontrado"));
        return service.listarDe(usuario.getId());
    }
}
