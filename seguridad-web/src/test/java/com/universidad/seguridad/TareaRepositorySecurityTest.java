package com.universidad.seguridad;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import com.universidad.seguridad.model.Tarea;
import com.universidad.seguridad.model.Usuario;
import com.universidad.seguridad.repository.TareaRepository;
import com.universidad.seguridad.repository.UsuarioRepository;

@SpringBootTest
@Transactional
class TareaRepositorySecurityTest {

    @Autowired
    private TareaRepository tareaRepository;

    @Autowired
    private UsuarioRepository usuarioRepository;

    @Test
    void trataLaEntradaDeSqlInjectionComoTextoLiteral() {
        Usuario usuario = new Usuario();
        usuario.setNombre("Usuario de prueba");
        usuario.setEmail("sql-test-" + UUID.randomUUID() + "@example.com");
        usuario.setContrasenia("hash-de-prueba");
        usuario.setRol("ROLE_USER");
        usuario = usuarioRepository.saveAndFlush(usuario);

        Tarea tarea = new Tarea();
        tarea.setTitulo("Tarea confidencial de prueba");
        tarea.setPropietario(usuario);
        tareaRepository.saveAndFlush(tarea);

        assertEquals(1, tareaRepository.findByPropietarioId(usuario.getId()).size());
        assertTrue(tareaRepository.buscarPorTitulo("' OR '1'='1").isEmpty());
    }
}
