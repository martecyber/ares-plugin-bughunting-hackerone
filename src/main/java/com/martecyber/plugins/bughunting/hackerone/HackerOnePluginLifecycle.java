package com.martecyber.plugins.bughunting.hackerone;

import com.martecyber.ares.plugins.PluginLifecycle;
import com.martecyber.ares.projects.ProjectTypeFacade;
import com.martecyber.ares.projects.ProjectTypeSpec;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;

/** Ensures the {@code BH_H1} project subtype exists and is enabled on install (as a child of
 *  {@code BH}, guaranteed to already exist since this plugin {@code dependsOn: ["bughunting"]});
 *  disables it (never deletes) on uninstall. */
public class HackerOnePluginLifecycle implements PluginLifecycle {

    private static final Logger log = LoggerFactory.getLogger(HackerOnePluginLifecycle.class);

    private final ProjectTypeFacade projectTypeFacade;

    public HackerOnePluginLifecycle(ProjectTypeFacade projectTypeFacade) {
        this.projectTypeFacade = projectTypeFacade;
    }

    @Override
    public void onInstall(JdbcTemplate jdbc) {
        projectTypeFacade.ensure(new ProjectTypeSpec("BH_H1", "HackerOne", "BH", "bughunting-hackerone", false, null));
        log.info("ares-plugin-bughunting-hackerone: 'BH_H1' project type enabled");
    }

    @Override
    public void onForget(JdbcTemplate jdbc) {
        projectTypeFacade.disable("BH_H1");
        log.info("ares-plugin-bughunting-hackerone: 'BH_H1' project type disabled");
    }
}
