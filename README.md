# Panel TPC

Panel interno de The Pickle Center: clientes, colaboradores, oportunidades, eventos, creadores, redes, equipo y tienda, con el estado de cada cosa.

Los datos van cifrados en `data.enc.json` (AES-GCM 256, clave derivada con PBKDF2) y solo se ven con la contraseña. Los datos en claro y la contraseña no están en este repositorio.

Actualizar: editar `privado/registros.json` en local y ejecutar `node scripts/cifrar.mjs`; después, subir `data.enc.json`.
