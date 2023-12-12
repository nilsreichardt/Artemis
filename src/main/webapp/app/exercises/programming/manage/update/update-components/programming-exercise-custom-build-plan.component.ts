import { Component, Input, OnChanges, SimpleChanges, ViewChild } from '@angular/core';
import { BuildAction, PlatformAction, ProgrammingExercise, ProgrammingLanguage, ProjectType, ScriptAction, WindFile } from 'app/entities/programming-exercise.model';
import { faQuestionCircle } from '@fortawesome/free-solid-svg-icons';
import { ProgrammingExerciseCreationConfig } from 'app/exercises/programming/manage/update/programming-exercise-creation-config';
import { AceEditorComponent } from 'app/shared/markdown-editor/ace-editor/ace-editor.component';
import { AeolusPreview, AeolusService } from 'app/exercises/programming/shared/service/aeolus.service';

@Component({
    selector: 'jhi-programming-exercise-custom-build-plan',
    templateUrl: './programming-exercise-custom-build-plan.component.html',
    styleUrls: ['../../programming-exercise-form.scss'],
})
export class ProgrammingExerciseCustomBuildPlanComponent implements OnChanges {
    @Input() programmingExercise: ProgrammingExercise;
    @Input() programmingExerciseCreationConfig: ProgrammingExerciseCreationConfig;

    programmingLanguage?: ProgrammingLanguage;
    projectType?: ProjectType;
    staticCodeAnalysisEnabled?: boolean;
    sequentialTestRuns?: boolean;
    testwiseCoverageEnabled?: boolean;

    constructor(private aeolusService: AeolusService) {}

    code: string = '#!/bin/bash\n\n# Add your custom build plan action here';
    active?: BuildAction = undefined;

    private _editor?: AceEditorComponent;
    private _generatedEditor?: AceEditorComponent;

    @ViewChild('generatedEditor', { static: false }) set generatedEditor(value: AceEditorComponent) {
        this._generatedEditor = value;
        if (this._generatedEditor) {
            this.setupGeneratorEditor();
            this._generatedEditor.setText('#!/bin/bash\n\n# Add your custom build plan action here\n\nexit 0');
        }
    }

    @ViewChild('editor', { static: false }) set editor(value: AceEditorComponent) {
        this._editor = value;
        if (this._editor) {
            this.setupEditor();
            this._editor.setText(this.code);
        }
    }

    ngOnChanges(changes: SimpleChanges) {
        if (changes.programmingExerciseCreationConfig || changes.programmingExercise) {
            if (this.shouldReloadTemplate()) {
                this.loadAeolusTemplate();
            }
        }
    }

    shouldReloadTemplate(): boolean {
        return (
            this.programmingExercise.programmingLanguage !== this.programmingLanguage ||
            this.programmingExercise.projectType !== this.projectType ||
            this.programmingExercise.staticCodeAnalysisEnabled !== this.staticCodeAnalysisEnabled ||
            this.programmingExercise.sequentialTestRuns !== this.sequentialTestRuns ||
            this.programmingExercise.testwiseCoverageEnabled !== this.testwiseCoverageEnabled
        );
    }

    /**
     * In case the programming language or project type changes, we need to reset the template and the build plan
     * @private
     */
    resetCustomBuildPlan() {
        this.programmingExercise.windFile = undefined;
        this.programmingExercise.buildPlanConfiguration = undefined;
    }
    /**
     * Loads the predefined template for the selected programming language and project type
     * if there is one available.
     * @private
     */
    loadAeolusTemplate() {
        this.resetCustomBuildPlan();
        if (!this.programmingExercise.programmingLanguage) {
            return;
        }
        this.programmingLanguage = this.programmingExercise.programmingLanguage;
        this.projectType = this.programmingExercise.projectType;
        this.staticCodeAnalysisEnabled = this.programmingExercise.staticCodeAnalysisEnabled;
        this.sequentialTestRuns = this.programmingExercise.sequentialTestRuns;
        this.testwiseCoverageEnabled = this.programmingExercise.testwiseCoverageEnabled;
        if (this.programmingExerciseCreationConfig.customBuildPlansSupported) {
            this.aeolusService
                .getAeolusTemplateFile(this.programmingLanguage, this.projectType, this.staticCodeAnalysisEnabled, this.sequentialTestRuns, this.testwiseCoverageEnabled)
                .subscribe({
                    next: (file) => {
                        if (file && !this.programmingExerciseCreationConfig.buildPlanLoaded) {
                            this.programmingExerciseCreationConfig.buildPlanLoaded = true;
                            const templateFile: WindFile = JSON.parse(file);
                            const windFile: WindFile = Object.assign(new WindFile(), templateFile);
                            const actions: BuildAction[] = [];
                            templateFile.actions.forEach((anyAction: any) => {
                                let action: BuildAction | undefined = undefined;
                                if (anyAction.script) {
                                    action = Object.assign(new ScriptAction(), anyAction);
                                } else {
                                    action = Object.assign(new PlatformAction(), anyAction);
                                }
                                if (!action) {
                                    return;
                                }
                                action.parameters = new Map<string, string | boolean | number>();
                                if (anyAction.parameters) {
                                    for (const key of Object.keys(anyAction.parameters)) {
                                        action.parameters.set(key, anyAction.parameters[key]);
                                    }
                                }
                                actions.push(action);
                            });
                            // somehow, the returned content has a scriptActions field, which is not defined in the WindFile class
                            delete windFile['scriptActions'];
                            windFile.actions = actions;
                            this.programmingExercise.windFile = windFile;
                        }
                    },
                    error: () => {
                        this.resetCustomBuildPlan();
                        this.programmingExerciseCreationConfig.buildPlanLoaded = true;
                    },
                });
        }
    }

    get editor(): AceEditorComponent | undefined {
        return this._editor;
    }

    get generatedEditor(): AceEditorComponent | undefined {
        return this._generatedEditor;
    }

    faQuestionCircle = faQuestionCircle;

    protected getActionScript(action: string): string {
        const foundAction: BuildAction | undefined = this.programmingExercise.windFile?.actions.find((a) => a.name === action);
        if (foundAction && foundAction instanceof ScriptAction) {
            return (foundAction as ScriptAction).script;
        }
        return '';
    }

    isScriptAction(action: BuildAction): boolean {
        return action instanceof ScriptAction;
    }

    changeActiveAction(action: string): void {
        if (!this.programmingExercise.windFile) {
            return;
        }

        this.code = this.getActionScript(action);
        this.active = this.programmingExercise.windFile.actions.find((a) => a.name === action);
        if (this.needsEditor() && this.editor) {
            this.editor.setText(this.code);
        }
    }

    protected needsEditor(): boolean {
        return this.active instanceof ScriptAction;
    }

    deleteAction(action: string): void {
        if (this.programmingExercise.windFile) {
            this.programmingExercise.windFile.actions = this.programmingExercise.windFile.actions.filter((a) => a.name !== action);
            if (this.active?.name === action) {
                this.active = undefined;
                this.code = '';
            }
            this.generatePreview();
        }
    }

    addAction(action: string): void {
        if (this.programmingExercise.windFile) {
            const newAction = new ScriptAction();
            newAction.script = '#!/bin/bash\n\n# Add your custom build plan action here\n\nexit 0';
            newAction.name = action;
            newAction.runAlways = false;
            this.programmingExercise.windFile.actions.push(newAction);
            this.changeActiveAction(action);
            this.generatePreview();
        }
    }

    addParameter(): void {
        if (this.active) {
            if (!this.active.parameters) {
                this.active.parameters = new Map<string, string | boolean | number>();
            }
            this.active.parameters.set('newParameter' + this.active.parameters.size, 'newValue');
        }
    }

    deleteParameter(key: string): void {
        if (this.active && this.active.parameters) {
            this.active.parameters.delete(key);
        }
    }

    generatePreview(): void {
        if (this.programmingExercise.windFile) {
            this.aeolusService.generatePreview(Object.assign({}, this.programmingExercise.windFile)).subscribe({
                next: (file) => {
                    const preview: AeolusPreview = Object.assign({}, JSON.parse(file));
                    this.generatedEditor?.setText(preview.result);
                },
                error: () => {
                    this.generatedEditor?.setText('#!/bin/bash\n\n# Add your custom build plan action here\n\nexit 0');
                },
            });
        }
    }

    codeChanged(code: string): void {
        if (this.active instanceof ScriptAction) {
            (this.active as ScriptAction).script = code;
            this.generatePreview();
        }
    }

    protected getParameterKeys(): string[] {
        if (this.active && this.active.parameters) {
            return Array.from(this.active.parameters.keys());
        }
        return [];
    }

    protected getParameter(key: string): string | number | boolean {
        if (this.active) {
            return this.active.parameters.get(key) ?? '';
        }
        return '';
    }

    /**
     * Sets up an ace editor for the template or solution file.
     */
    setupEditor(): void {
        if (!this._editor) {
            return;
        }
        this._editor.getEditor().setOptions({
            animatedScroll: true,
            maxLines: 20,
            showPrintMargin: false,
            readOnly: false,
            highlightActiveLine: false,
            highlightGutterLine: false,
            minLines: 20,
            mode: 'ace/mode/sh',
        });
        this._editor.getEditor().renderer.setOptions({
            showFoldWidgets: false,
        });
    }
    /**
     * Sets up an ace editor for the template or solution file.
     */
    setupGeneratorEditor(): void {
        if (!this._generatedEditor) {
            return;
        }
        this._generatedEditor.getEditor().setOptions({
            animatedScroll: true,
            maxLines: 35,
            showPrintMargin: false,
            readOnly: false,
            highlightActiveLine: false,
            highlightGutterLine: false,
            minLines: 35,
            mode: 'ace/mode/sh',
        });
        this._generatedEditor.getEditor().renderer.setOptions({
            showFoldWidgets: false,
        });
    }
}
