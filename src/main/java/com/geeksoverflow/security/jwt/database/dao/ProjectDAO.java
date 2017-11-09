package com.geeksoverflow.security.jwt.database.dao;

import java.io.Serializable;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.orm.hibernate4.HibernateTemplate;
import org.springframework.stereotype.Service;

import com.geeksoverflow.security.jwt.database.model.Project;


/**
 * @author <a href="mailto:sunil.pulugula@wavemaker.com">Sunil Kumar</a>
 * @since 5/11/17
 */
@Service
public class ProjectDAO implements GenericDao<Project, String> {

    @Autowired
    private HibernateTemplate template;

    @Override
    public Project load(final String id) {
        return template.load(Project.class, id);
    }

    @Override
    public Project get(final String id) {
        return template.get(Project.class, id);
    }

    public List<Project> getProjectsByUser(String userId) {

        return (List<Project>) template.findByNamedParam("from Project where USER_ID=:userid", "userid", userId);
    }

    @Override
    public List<Project> getAll() {
        return template.loadAll(Project.class);
    }

    @Override
    public Serializable save(final Project object) {
        return template.save(object);
    }

    @Override
    public void saveOrUpdate(final Project object) {
        template.saveOrUpdate(object);
    }

    @Override
    public void delete(final Project object) {
        template.delete(object);
    }

    @Override
    public Long count() {
        return new Long(template.loadAll(Project.class).size());
    }

    @Override
    public void flush() {
        template.flush();
    }
}